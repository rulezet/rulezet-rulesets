rule APT_MAL_LUA_Hunting_Lua_SEASPRAY_1 {
    meta:
        author = "Mandiant"
        date = "2023-06-15"
        reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
        description = "Hunting rule looking for strings observed in SEASPRAY samples."
        hash = "35cf6faf442d325961935f660e2ab5a0"
        score = 70
        id = "8c744b85-b61e-56d0-8a9e-ae6a954e1b95"
    strings:
        $str1 = "string.find(attachment:filename(),'obt075') ~= nil" 
        $str2 = "os.execute('cp '..tostring(tmpfile)..' /tmp/'..attachment:filename())" 
        $str3 = "os.execute('rverify'..' /tmp/'..attachment:filename())" 
    condition:
        all of them
}