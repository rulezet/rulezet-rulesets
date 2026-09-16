rule APT_MAL_Hunting_LUA_SEASIDE_1 {
    meta:
        description = "Hunting rule looking for strings observed in SEASIDE samples."
        author = "Mandiant"
        date = "2023-06-15"
        score = 70
        reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
        hash = "cd2813f0260d63ad5adf0446253c2172"
        id = "86eaff7b-4ca0-53cd-8886-da66a36c778f"
    strings:
        $s1 = "function on_helo()"
        $s2 = "local bindex,eindex = string.find(helo,'.onion')" 
        $s3 = "helosend = 'pd'..' '..helosend" 
        $s4 = "os.execute(helosend)" 
    condition:
        filesize < 1MB and all of ($s*)
}