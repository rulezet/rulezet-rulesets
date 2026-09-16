rule sqlmap
{
    meta:
        description = "Detection patterns for the tool 'sqlmap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sqlmap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --batch --dbs"
                        $string2 = " --batch --password"
                        $string3 = " --check-tor "
                        $string4 = " --crawl="
                        $string5 = " --dbms=mysql -u "
                        $string6 = " --msf-path"
                        $string7 = " --os-bof"
                        $string8 = " --os-cmd whoami"
                        $string9 = " --os-pwn"
                        $string10 = " --os-smbrelay"
                        $string11 = " --priv-esc"
                        $string12 = " --random-agent "
                        $string13 = " --sql-shell"
                        $string14 = " --tor "
                        $string15 = " --tor-port"
                        $string16 = " --tor-type"
                        $string17 = /\s\-u\s.{0,100}http.{0,100}\s\-\-dbs/
                        $string18 = /\s\-u\s.{0,100}http.{0,100}\s\-\-os\-shell/
                        $string19 = /\s\-\-union\-char\s.{0,100}GsFRts2/
                        $string20 = "/Sqlmap"
                        $string21 = /\/vulnserver\.py/
                        $string22 = /backdoor\.asp/
                        $string23 = /backdoor\.aspx/
                        $string24 = /backdoor\.jsp/
                        $string25 = /backdoor\.php/
                        $string26 = "--batch --dump -T "
                        $string27 = "data/shell/backdoors"
                        $string28 = "data/shell/stagers"
                        $string29 = "--file-read=/etc/passwd"
                        $string30 = /icmpsh\.exe/ nocase ascii wide
                        $string31 = /icmpsh_m\.py/
                        $string32 = /icmpsh\-m\.c/
                        $string33 = /icmpsh\-m\.pl/
                        $string34 = /shellcodeexec\.x32/
                        $string35 = /shellcodeexec\.x64/
                        $string36 = "sqlmap -"
                        $string37 = /sqlmap\.conf/
                        $string38 = /sqlmap\.py/
                        $string39 = "sqlmapapi -"
                        $string40 = /sqlmapapi\.py/
                        $string41 = "sqlmapproject/sqlmap"
                        $string42 = /xforwardedfor\.py/
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