rule ROADtools
{
    meta:
        description = "Detection patterns for the tool 'ROADtools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ROADtools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sauth\s\-\-prt\s.{0,100}\s\-\-prt\-sessionkey\s/ nocase ascii wide
                        $string2 = "/ROADtools/" nocase ascii wide
                        $string3 = /\\ROADtools\\/ nocase ascii wide
                        $string4 = "1e2136c0b4bef6f7a9de7cd1d57d2c5f3dae7f90116b50454db495970d0fe251" nocase ascii wide
                        $string5 = /dirkjan\@outsidersecurity\.nl/ nocase ascii wide
                        $string6 = /install\s.{0,100}\sroadrecon/
                        $string7 = "pip install roadlib" nocase ascii wide
                        $string8 = "pip install roadrecon" nocase ascii wide
                        $string9 = "pip install roadtx" nocase ascii wide
                        $string10 = "roadrecon auth " nocase ascii wide
                        $string11 = "roadrecon dump " nocase ascii wide
                        $string12 = "roadrecon gather " nocase ascii wide
                        $string13 = "roadrecon plugin " nocase ascii wide
                        $string14 = /roadrecon.{0,100}gather\.py/ nocase ascii wide
                        $string15 = /roadrecon\.db/ nocase ascii wide
                        $string16 = "roadrecon/frontend" nocase ascii wide
                        $string17 = /ROADtools\.git/ nocase ascii wide
                        $string18 = /roadtools\.roadlib\.auth/ nocase ascii wide
                        $string19 = /roadtools\.roadtx\.main\:main/ nocase ascii wide
                        $string20 = "ROADtools-master" nocase ascii wide
                        $string21 = "roadtx browserprtinject " nocase ascii wide
                        $string22 = "roadtx device -a delete " nocase ascii wide
                        $string23 = "roadtx getscope -s" nocase ascii wide
                        $string24 = "roadtx gettokens -u " nocase ascii wide
                        $string25 = "roadtx interactiveauth -c " nocase ascii wide
                        $string26 = "roadtx keepassauth -" nocase ascii wide
                        $string27 = /roadtx\sprt\s\-u\s.{0,100}\-\-key\-pem\s/ nocase ascii wide
                        $string28 = "roadtx prtauth -" nocase ascii wide
                        $string29 = "roadtx refreshtokento -" nocase ascii wide
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