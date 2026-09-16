rule rule_dumper2020_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dumper2020' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dumper2020"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dumper2020_offensive_tool_keyword = /\/dumper2020\.git/ nocase ascii wide
                        $string2_dumper2020_offensive_tool_keyword = "/dumper2020_exe" nocase ascii wide
                        $string3_dumper2020_offensive_tool_keyword = /\[\+\]\sCaptured\ssnapshot\sof\sLSASS\sprocess/ nocase ascii wide
                        $string4_dumper2020_offensive_tool_keyword = /\[\+\]\sSuccessfully\sopened\sLSASS\,\sPID\:\s/ nocase ascii wide
                        $string5_dumper2020_offensive_tool_keyword = /\\dumper2020_exe/ nocase ascii wide
                        $string6_dumper2020_offensive_tool_keyword = /\\dumper2020_exe\.cpp/ nocase ascii wide
                        $string7_dumper2020_offensive_tool_keyword = /\\dumper2020\-master/ nocase ascii wide
                        $string8_dumper2020_offensive_tool_keyword = "1b591c180e6c5221a81921e42b0256b62cec1f1af872624f5fd178d1ed7bd7c6" nocase ascii wide
                        $string9_dumper2020_offensive_tool_keyword = "399399f17d32ec67656ef826a7efc16e48fb10f5b59da6b2d57feca3676a8190" nocase ascii wide
                        $string10_dumper2020_offensive_tool_keyword = "423091502099d1c9adba971a42db7801b2e856c1fd5bed6f1ca70d0e39ca1a94" nocase ascii wide
                        $string11_dumper2020_offensive_tool_keyword = "84A7E50E-B0F0-4B3D-98CD-F32CDB1EB8CA" nocase ascii wide
                        $string12_dumper2020_offensive_tool_keyword = "a48708d0c27daec437448a1363e63b53d518cf00e60d701fe5f6292ffab1df00" nocase ascii wide
                        $string13_dumper2020_offensive_tool_keyword = "B7355478-EEE0-46A7-807A-23CF0C5295AE" nocase ascii wide
                        $string14_dumper2020_offensive_tool_keyword = "D8091ED0-5E78-4AF5-93EE-A5AA6E978430" nocase ascii wide
                        $string15_dumper2020_offensive_tool_keyword = "ee30d8fb660ce3a25a8664c6214f2766a7099bdd78392009d961d22b7fd3ded2" nocase ascii wide
                        $string16_dumper2020_offensive_tool_keyword = "gitjdm/dumper2020" nocase ascii wide
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