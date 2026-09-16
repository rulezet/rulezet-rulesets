rule bofhound
{
    meta:
        description = "Detection patterns for the tool 'bofhound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bofhound"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " Brc4LdapSentinelParser" nocase ascii wide
                        $string2 = " --brute-ratel" nocase ascii wide
                        $string3 = /\/beacon_202_no_acl\.log/
                        $string4 = /\/beacon_257\-objects\.log/
                        $string5 = /\/bloodhound_domain\.py/ nocase ascii wide
                        $string6 = /\/bloodhound_domaintrust\.py/ nocase ascii wide
                        $string7 = /\/bloodhound_gpo\.py/ nocase ascii wide
                        $string8 = /\/bloodhound_object\.py/ nocase ascii wide
                        $string9 = /\/bloodhound_ou\.py/ nocase ascii wide
                        $string10 = /\/bloodhound_schema\.py/ nocase ascii wide
                        $string11 = /\/bofhound\.git/ nocase ascii wide
                        $string12 = /\/ldap_search_bof\.py/ nocase ascii wide
                        $string13 = "/opt/cobaltstrike/logs"
                        $string14 = /\\ldap_search_bof\.py/ nocase ascii wide
                        $string15 = /badger_no_acl_1030_objects\.log/ nocase ascii wide
                        $string16 = "bofhound --" nocase ascii wide
                        $string17 = "bofhound -i " nocase ascii wide
                        $string18 = "bofhound -o " nocase ascii wide
                        $string19 = "bofhound-main" nocase ascii wide
                        $string20 = /brc4_ldap_sentinel\.py/ nocase ascii wide
                        $string21 = "fortalice/bofhound" nocase ascii wide
                        $string22 = "from bofhound import " nocase ascii wide
                        $string23 = /from\sbofhound\.ad\simport/ nocase ascii wide
                        $string24 = "import LdapSearchBofParser" nocase ascii wide
                        $string25 = "pip3 install bofhound" nocase ascii wide
                        $string26 = "poetry run bofhound" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}