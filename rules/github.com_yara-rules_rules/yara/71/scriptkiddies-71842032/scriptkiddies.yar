rule scriptkiddies {
    strings:
        $ = "lastc0de@Outlook.com" nocase
        $ = "CodersLeet" nocase
        $ = "AgencyCaFc" nocase
        $ = "IndoXploit" nocase
        $ = "Kapaljetz666" nocase
    condition: 
        any of them and filesize < 500KB
}