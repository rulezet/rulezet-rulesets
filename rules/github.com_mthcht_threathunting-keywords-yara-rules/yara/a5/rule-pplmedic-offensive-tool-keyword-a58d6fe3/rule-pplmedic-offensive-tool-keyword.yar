rule rule_PPLmedic_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PPLmedic' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PPLmedic"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PPLmedic_offensive_tool_keyword = /\sPPLmedic\.exe/ nocase ascii wide
                        $string2_PPLmedic_offensive_tool_keyword = /\/PPLmedic\.exe/ nocase ascii wide
                        $string3_PPLmedic_offensive_tool_keyword = /\/PPLmedic\.git/ nocase ascii wide
                        $string4_PPLmedic_offensive_tool_keyword = /\[\+\]\sPayload\sDLL\ssuccessfully\sloaded\safter/ nocase ascii wide
                        $string5_PPLmedic_offensive_tool_keyword = /\\\\PPLmedic\\\\ntstuff/ nocase ascii wide
                        $string6_PPLmedic_offensive_tool_keyword = /\\ExploitElevate\.cpp/ nocase ascii wide
                        $string7_PPLmedic_offensive_tool_keyword = /\\PPLmedic\.cpp/ nocase ascii wide
                        $string8_PPLmedic_offensive_tool_keyword = /\\PPLmedic\.exe/ nocase ascii wide
                        $string9_PPLmedic_offensive_tool_keyword = /\\PPLmedic\\PPLmedic/ nocase ascii wide
                        $string10_PPLmedic_offensive_tool_keyword = /\\Temp\\csrss\.dmp/ nocase ascii wide
                        $string11_PPLmedic_offensive_tool_keyword = /\\Temp\\lsass\.dmp/ nocase ascii wide
                        $string12_PPLmedic_offensive_tool_keyword = "29CBBC24-363F-42D7-B018-5EF068BA8777" nocase ascii wide
                        $string13_PPLmedic_offensive_tool_keyword = "4d2f66539f067f631db31039ec81707028bb37efcd2ebbf86a1a920d60d75263" nocase ascii wide
                        $string14_PPLmedic_offensive_tool_keyword = "ac49d2041cd57b1efba672c3305b621ebb265380010b8951cda01c055a7e1e64" nocase ascii wide
                        $string15_PPLmedic_offensive_tool_keyword = "db03400af112a7969ba2d68288b9dc908b2d234d62184fd5f01079749c4bf09e" nocase ascii wide
                        $string16_PPLmedic_offensive_tool_keyword = "F00A3B5F-D9A9-4582-BBCE-FD10EFBF0C17" nocase ascii wide
                        $string17_PPLmedic_offensive_tool_keyword = "fa06c45e4522706565bea7e2532ba67cf2cad3e57e38157c09e46445c1dd100a" nocase ascii wide
                        $string18_PPLmedic_offensive_tool_keyword = "itm4n/PPLmedic" nocase ascii wide
                        $string19_PPLmedic_offensive_tool_keyword = /PPLmedicDll\.def/ nocase ascii wide
                        $string20_PPLmedic_offensive_tool_keyword = /PPLmedicDll\.dll/ nocase ascii wide
                        $string21_PPLmedic_offensive_tool_keyword = /WaaSMedicPayload\.dll/ nocase ascii wide
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