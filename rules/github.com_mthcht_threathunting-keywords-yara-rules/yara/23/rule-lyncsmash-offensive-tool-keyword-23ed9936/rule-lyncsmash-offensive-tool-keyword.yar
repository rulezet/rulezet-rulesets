rule rule_lyncsmash_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'lyncsmash' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lyncsmash"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_lyncsmash_offensive_tool_keyword = /\.py\sdiscover\s\-H\sdomain_list\.txt/ nocase ascii wide
                        $string2_lyncsmash_offensive_tool_keyword = /\.py\senum\s\-H\s.{0,100}\s\-U\s.{0,100}\.txt\s\-P\s.{0,100}\.txt\s\-.{0,100}\.txt/ nocase ascii wide
                        $string3_lyncsmash_offensive_tool_keyword = /\.py\slock\s\-H\s.{0,100}\s\-u\sadministrator\s\-d\s/ nocase ascii wide
                        $string4_lyncsmash_offensive_tool_keyword = /\/find_domain\.sh/ nocase ascii wide
                        $string5_lyncsmash_offensive_tool_keyword = "/lyncsmash/" nocase ascii wide
                        $string6_lyncsmash_offensive_tool_keyword = /\/wordlists\/owa_directories\.txt/ nocase ascii wide
                        $string7_lyncsmash_offensive_tool_keyword = /\/wordlists\/skype\-directories\.txt/ nocase ascii wide
                        $string8_lyncsmash_offensive_tool_keyword = /1_FindDomain\.sh/ nocase ascii wide
                        $string9_lyncsmash_offensive_tool_keyword = /2_lyncbrute\.sh/ nocase ascii wide
                        $string10_lyncsmash_offensive_tool_keyword = /alexa\-top\-20000\-sites\.txt/ nocase ascii wide
                        $string11_lyncsmash_offensive_tool_keyword = /brute_force_ntlm\.sh/ nocase ascii wide
                        $string12_lyncsmash_offensive_tool_keyword = /find_domain\.sh\s/
                        $string13_lyncsmash_offensive_tool_keyword = "lyncsmash" nocase ascii wide
                        $string14_lyncsmash_offensive_tool_keyword = /lyncsmash\.git/ nocase ascii wide
                        $string15_lyncsmash_offensive_tool_keyword = /lyncsmash\.log/ nocase ascii wide
                        $string16_lyncsmash_offensive_tool_keyword = /lyncsmash\.py/ nocase ascii wide
                        $string17_lyncsmash_offensive_tool_keyword = "lyncsmash-master" nocase ascii wide
                        $string18_lyncsmash_offensive_tool_keyword = /ntlm\-info\.py/ nocase ascii wide
                        $string19_lyncsmash_offensive_tool_keyword = "nyxgeek/lyncsmash" nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}