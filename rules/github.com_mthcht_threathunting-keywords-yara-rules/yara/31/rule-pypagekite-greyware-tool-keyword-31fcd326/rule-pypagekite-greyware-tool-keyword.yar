rule rule_PyPagekite_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PyPagekite' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PyPagekite"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_PyPagekite_greyware_tool_keyword = " install xvnc4viewer netcat-traditional socat" nocase ascii wide
                        $string2_PyPagekite_greyware_tool_keyword = /\spagekite\.logging/ nocase ascii wide
                        $string3_PyPagekite_greyware_tool_keyword = /\spagekite\.py/ nocase ascii wide
                        $string4_PyPagekite_greyware_tool_keyword = /\spagekite\-gtk\.py/ nocase ascii wide
                        $string5_PyPagekite_greyware_tool_keyword = "\"PageKite system service\"" nocase ascii wide
                        $string6_PyPagekite_greyware_tool_keyword = /\/etc\/pagekite\.d/
                        $string7_PyPagekite_greyware_tool_keyword = /\/pagekite\-.{0,100}\.log/
                        $string8_PyPagekite_greyware_tool_keyword = /\/pagekite\.log/
                        $string9_PyPagekite_greyware_tool_keyword = /\/pagekite\.py/ nocase ascii wide
                        $string10_PyPagekite_greyware_tool_keyword = /\/pagekite\-0\.3\.21\.py/ nocase ascii wide
                        $string11_PyPagekite_greyware_tool_keyword = /\/pagekite\-0\.4\.6a\.py/ nocase ascii wide
                        $string12_PyPagekite_greyware_tool_keyword = /\/pagekite\-0\.5\.6d\.py/ nocase ascii wide
                        $string13_PyPagekite_greyware_tool_keyword = /\/pagekite\-0\.5\.8a\.py/ nocase ascii wide
                        $string14_PyPagekite_greyware_tool_keyword = /\/pagekite\-gtk\.py/ nocase ascii wide
                        $string15_PyPagekite_greyware_tool_keyword = /\/pagekite\-tmp\.py/
                        $string16_PyPagekite_greyware_tool_keyword = /\/PyPagekite\.git/ nocase ascii wide
                        $string17_PyPagekite_greyware_tool_keyword = "/PyPagekite/tarball/" nocase ascii wide
                        $string18_PyPagekite_greyware_tool_keyword = "/PyPagekite/zipball/" nocase ascii wide
                        $string19_PyPagekite_greyware_tool_keyword = "/var/log/pagekite/"
                        $string20_PyPagekite_greyware_tool_keyword = /\/var\/run\/pagekite\.pid/
                        $string21_PyPagekite_greyware_tool_keyword = /\[PageKite\]\sRemote\sconnection\sclosed\!/ nocase ascii wide
                        $string22_PyPagekite_greyware_tool_keyword = /\\pagekite\.cfg/ nocase ascii wide
                        $string23_PyPagekite_greyware_tool_keyword = /\\pagekite\.py/ nocase ascii wide
                        $string24_PyPagekite_greyware_tool_keyword = /\\pagekite\-gtk\.py/ nocase ascii wide
                        $string25_PyPagekite_greyware_tool_keyword = "23e8d0a95d5769ea14e4fd5eac6b5c111ce538e61b18492c21482afd015170eb" nocase ascii wide
                        $string26_PyPagekite_greyware_tool_keyword = "7270581d315cffb125f9ac64ebcb6622959c8e9f779b8a07808fd6929b0e746a" nocase ascii wide
                        $string27_PyPagekite_greyware_tool_keyword = "7dc50c28dc7c2fa9a6ea80df35c06bd649b17ae86d333e88b3bf242ac5690c98" nocase ascii wide
                        $string28_PyPagekite_greyware_tool_keyword = "b01db099512e344df190ee405619399c835b1d5522e2e6faa8e47b49418bab66" nocase ascii wide
                        $string29_PyPagekite_greyware_tool_keyword = "be8fc36ec0082bdb7d20a21ae7098899529bc9b9f6439b1496ca634395598d8a" nocase ascii wide
                        $string30_PyPagekite_greyware_tool_keyword = /bre\@pagekite\.net/ nocase ascii wide
                        $string31_PyPagekite_greyware_tool_keyword = "c4ec5f4d04c44b7a1c8cf813435dbc66a541b450bbaca4d70ded985d6518e76a" nocase ascii wide
                        $string32_PyPagekite_greyware_tool_keyword = "f16d1b7d69bf4c2a9a7e737809dd930012f419e7b7977887226f0f6859367cc4" nocase ascii wide
                        $string33_PyPagekite_greyware_tool_keyword = "f2fd6676dba233df558278e6be42cd4c50a78a9c3f879db87acfc96607f41331" nocase ascii wide
                        $string34_PyPagekite_greyware_tool_keyword = /http\:\/\/.{0,100}\.pagekite\.me/ nocase ascii wide
                        $string35_PyPagekite_greyware_tool_keyword = /http\:\/\/up\.pagekite\.net\// nocase ascii wide
                        $string36_PyPagekite_greyware_tool_keyword = /https\:\/\/.{0,100}\.pagekite\.me/ nocase ascii wide
                        $string37_PyPagekite_greyware_tool_keyword = /https\:\/\/pagekite\.net\/downloads\// nocase ascii wide
                        $string38_PyPagekite_greyware_tool_keyword = /https\:\/\/pagekite\.net\/pk\/src\// nocase ascii wide
                        $string39_PyPagekite_greyware_tool_keyword = /kitename\.pagekite\.me/ nocase ascii wide
                        $string40_PyPagekite_greyware_tool_keyword = /pagekite\.httpd/ nocase ascii wide
                        $string41_PyPagekite_greyware_tool_keyword = /pagekite\.py\s\// nocase ascii wide
                        $string42_PyPagekite_greyware_tool_keyword = /pagekite\.py\s443\shttps\:\/\// nocase ascii wide
                        $string43_PyPagekite_greyware_tool_keyword = /pagekite\.py\s80\shttp\:\/\// nocase ascii wide
                        $string44_PyPagekite_greyware_tool_keyword = /pagekite\.py\s\-\-add\s/ nocase ascii wide
                        $string45_PyPagekite_greyware_tool_keyword = /pagekite\.py\slocalhost\:/ nocase ascii wide
                        $string46_PyPagekite_greyware_tool_keyword = "pagekite/PyPagekite" nocase ascii wide
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