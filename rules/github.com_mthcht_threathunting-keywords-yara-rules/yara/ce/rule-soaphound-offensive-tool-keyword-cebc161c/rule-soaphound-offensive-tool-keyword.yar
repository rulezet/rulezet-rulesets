rule rule_SOAPHound_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SOAPHound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SOAPHound"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SOAPHound_offensive_tool_keyword = " --bhdump " nocase ascii wide
                        $string2_SOAPHound_offensive_tool_keyword = " --certdump " nocase ascii wide
                        $string3_SOAPHound_offensive_tool_keyword = " --dnsdump " nocase ascii wide
                        $string4_SOAPHound_offensive_tool_keyword = /\sSOAPHound\.ADWS/ nocase ascii wide
                        $string5_SOAPHound_offensive_tool_keyword = /\\"ADWS\srequest\swith\sldapbase\s\(/ nocase ascii wide
                        $string6_SOAPHound_offensive_tool_keyword = "\"Dump BH data\"" nocase ascii wide
                        $string7_SOAPHound_offensive_tool_keyword = /\(\!soaphound\=/ nocase ascii wide
                        $string8_SOAPHound_offensive_tool_keyword = /\.exe\s\s\-\-buildcache\s\-c\s.{0,100}\\cache\.txt/ nocase ascii wide
                        $string9_SOAPHound_offensive_tool_keyword = /\.exe\s\-\-showstats\s\-c\s.{0,100}\\cache\.txt/ nocase ascii wide
                        $string10_SOAPHound_offensive_tool_keyword = /\/SOAPHound\.exe/ nocase ascii wide
                        $string11_SOAPHound_offensive_tool_keyword = /\/SOAPHound\.git/ nocase ascii wide
                        $string12_SOAPHound_offensive_tool_keyword = /\/SOAPHound\/Program\.cs/ nocase ascii wide
                        $string13_SOAPHound_offensive_tool_keyword = /\\SOAPHound\.csproj/ nocase ascii wide
                        $string14_SOAPHound_offensive_tool_keyword = /\\SOAPHound\.exe/ nocase ascii wide
                        $string15_SOAPHound_offensive_tool_keyword = /\\SOAPHound\.sln/ nocase ascii wide
                        $string16_SOAPHound_offensive_tool_keyword = /\\SOAPHound\\Enums\\/ nocase ascii wide
                        $string17_SOAPHound_offensive_tool_keyword = /\\SOAPHound\\Program\.cs/ nocase ascii wide
                        $string18_SOAPHound_offensive_tool_keyword = /\\SOAPHound\-master/ nocase ascii wide
                        $string19_SOAPHound_offensive_tool_keyword = "33571B09-4E94-43CB-ABDC-0226D769E701" nocase ascii wide
                        $string20_SOAPHound_offensive_tool_keyword = /Domain\scontroller\sis\smissing.{0,100}\suse\s\-\-dc\./ nocase ascii wide
                        $string21_SOAPHound_offensive_tool_keyword = "Dump AD Certificate Services data" nocase ascii wide
                        $string22_SOAPHound_offensive_tool_keyword = "Dump AD Integrated DNS data" nocase ascii wide
                        $string23_SOAPHound_offensive_tool_keyword = "FalconForceTeam/SOAPHound" nocase ascii wide
                        $string24_SOAPHound_offensive_tool_keyword = "Password to use for ADWS Connection" nocase ascii wide
                        $string25_SOAPHound_offensive_tool_keyword = /SOAPHound\sPoC\s1\.0\.1\-beta/ nocase ascii wide
                        $string26_SOAPHound_offensive_tool_keyword = /SOAPHound\.exe\s/ nocase ascii wide
                        $string27_SOAPHound_offensive_tool_keyword = /SOAPHound\.Processors/ nocase ascii wide
                        $string28_SOAPHound_offensive_tool_keyword = "Specify domain for enumeration" nocase ascii wide
                        $string29_SOAPHound_offensive_tool_keyword = /Username\sto\suse\sfor\sADWS\sConnection\.\sFormat\:\sdomain\\\\user\sor\suser\@domain/ nocase ascii wide
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