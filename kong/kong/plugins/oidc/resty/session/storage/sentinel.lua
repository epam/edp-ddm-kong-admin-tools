local setmetatable  = setmetatable
local tonumber      = tonumber
local concat        = table.concat
local sleep         = ngx.sleep
local null          = ngx.null
local var           = ngx.var

local UNLOCK = [[
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
else
    return 0
end
]]

local function enabled(value)
    if value == nil then return nil end
    return value == true or (value == "1" or value == "true" or value == "on")
end

local function ifnil(value, default)
    if value == nil then
        return default
    end

    return enabled(value)
end

local storage = {}

storage.__index = storage

function storage.new(session)
    ngx.log(ngx.DEBUG, "storage:new()")

    local config  = session.sentinel

    local self = {
        prefix          = config.prefix                     or "sessions",
        uselocking      = ifnil(config.uselocking, true),
        spinlockwait    = tonumber(config.spinlockwait, 10) or 150,
        maxlockwait     = tonumber(config.maxlockwait,  10) or 30,
        connect_timeout = tonumber(config.connect_timeout,  10) or 50,
        send_timeout    = tonumber(config.send_timeout,  10) or 5000,
        read_timeout    = tonumber(config.read_timeout,  10) or 5000,
        keepalive_timeout = tonumber(config.keepalive_timeout,  10) or 30000,
        sentinel_host   = config.sentinel_host or "127.0.0.1",
        sentinel_port   = tonumber(config.sentinel_port, 10) or 26379,
        redis_auth_user = os.getenv("REDIS_AUTH_USER") or config.redis_auth_user or "",
        redis_auth_secret = os.getenv("REDIS_AUTH_SECRET") or config.redis_auth_secret or "",
        sentinel_master_name = config.sentinel_master_name or "mymaster",
        sentinel_role = config.sentinel_role or "m",
        sentinel_db = config.sentinel_db or "sessions",
        sentinel_config = config,
        redis = nil
    }

    self.sc = require("resty.redis.connector").new({
        connect_timeout = self.connect_timeout,
        send_timeout = self.send_timeout,
        read_timeout = self.read_timeout,
        keepalive_timeout = self.keepalive_timeout})

    return setmetatable(self, storage)
end

function storage:connect()
    ngx.log(ngx.DEBUG, "storage:connect(), host:" .. self.sentinel_host .. ":" .. self.sentinel_port)

    local sentinel, err = self.sc:connect({
        url = "sentinel://" .. self.redis_auth_user .. ":" .. self.redis_auth_secret .. "@" .. self.sentinel_master_name .. ":" .. self.sentinel_role .. "/" .. self.sentinel_db,
        sentinels = {
            { host = self.sentinel_host, port = self.sentinel_port }
        }
    })

    if not sentinel then
        ngx.log(ngx.ERR, "Failed to connect to Sentinel [" .. self.sentinel_host .. ":" .. self.sentinel_port .. "]:" .. err)
        return nil, err
    end
    ngx.log(ngx.DEBUG, "storage:connect() succeeded")

    self.redis = sentinel

    return sentinel, err
end

function storage:set_keepalive()
    ngx.log(ngx.DEBUG, "storage:set_keepalive()")

    return self.redis:set_keepalive(self.pool_timeout)
end

function storage:key(id)
    return concat({ self.prefix, id }, ":" )
end

function storage:lock(key)
    ngx.log(ngx.DEBUG, "storage:lock(), key:" .. key)
    if not self.uselocking or self.locked then
        return true
    end

    if not self.token then
        self.token = var.request_id
    end

    local lock_key = concat({ key, "lock" }, "." )
    local lock_ttl = self.maxlockwait + 1
    local attempts = (1000 / self.spinlockwait) * self.maxlockwait
    local waittime = self.spinlockwait / 1000

    for _ = 1, attempts do
        local ok = self.redis:set(lock_key, self.token, "EX", lock_ttl, "NX")
        if ok ~= null then
            self.locked = true
            return true
        end

        sleep(waittime)
    end

    return false, "unable to acquire a session lock"
end

function storage:unlock(key)
    ngx.log(ngx.DEBUG, "storage:unlock(), key:" .. key)
    if not self.uselocking or not self.locked then
        return
    end

    local lock_key = concat({ key, "lock" }, "." )

    self.redis:eval(UNLOCK, 1, lock_key, self.token)
    self.locked = nil
end

function storage:get(key)
    ngx.log(ngx.DEBUG, "storage:get(), key:" .. key)
    local data, err = self.redis:get(key)
    if not data then
        ngx.log(ngx.WARN, "storage:get(), no data for key: " .. key)
        return nil, err
    end

    if data == null then
        ngx.log(ngx.WARN, "storage:get(), nil data for key: " .. key)
        return nil
    end

    return data
end

function storage:set(key, data, lifetime)
    ngx.log(ngx.DEBUG, "storage:set(), key:" .. key)
    return self.redis:setex(key, lifetime, data)
end

function storage:expire(key, lifetime)
    ngx.log(ngx.DEBUG, "storage:expire(), key:" .. key)
    return self.redis:expire(key, lifetime)
end

function storage:delete(key)
    ngx.log(ngx.DEBUG, "storage:delete(), key:" .. key)
    return self.redis:del(key)
end

function storage:open(id, keep_lock)
    ngx.log(ngx.DEBUG, "storage:open(), id:" .. id)
    local ok, err = self:connect()
    if not ok then
        return nil, err
    end

    local key = self:key(id)

    ok, err = self:lock(key)
    if not ok then
        self:set_keepalive()
        return nil, err
    end

    local data
    data, err = self:get(key)

    if err or not data or not keep_lock then
        self:unlock(key)
    end
    self:set_keepalive()

    return data, err
end

function storage:start(id)
    ngx.log(ngx.DEBUG, "storage:start(), id:" .. id)
    if not self.uselocking or not self.locked then
        return true
    end

    local ok, err = self:connect()
    if not ok then
        return nil, err
    end

    ok, err = self:lock(self:key(id))

    self:set_keepalive()

    return ok, err
end

function storage:save(id, ttl, data, close)
    ngx.log(ngx.DEBUG, "storage:save(), id:" .. id)
    local ok, err = self:connect()
    if not ok then
        return nil, err
    end

    local key = self:key(id)

    ok, err = self:set(key, data, ttl)

    if close then
        self:unlock(key)
    end

    self:set_keepalive()

    if not ok then
        return nil, err
    end

    return true
end

function storage:close(id)
    ngx.log(ngx.DEBUG, "storage:close(), id:" .. id)
    if not self.uselocking or not self.locked then
        return true
    end

    local ok, err = self:connect()
    if not ok then
        return nil, err
    end

    local key = self:key(id)

    self:unlock(key)
    self:set_keepalive()

    return true
end

function storage:destroy(id)
    ngx.log(ngx.DEBUG, "storage:destroy(), id:" .. id)
    local ok, err = self:connect()
    if not ok then
        return nil, err
    end

    local key = self:key(id)

    ok, err = self:ttl(key, 60)

    self:unlock(key)
    self:set_keepalive()

    return ok, err
end

function storage:ttl(id, ttl, close)
    ngx.log(ngx.DEBUG, "storage:ttl(), id:" .. id .. " ttl:" .. ttl)
    local ok, err = self:connect()
    if not ok then
        return nil, err
    end

    local key = self:key(id)

    ok, err = self:expire(key, ttl)

    if close then
        self:unlock(key)
    end

    self:set_keepalive()

    return ok, err
end

return storage
