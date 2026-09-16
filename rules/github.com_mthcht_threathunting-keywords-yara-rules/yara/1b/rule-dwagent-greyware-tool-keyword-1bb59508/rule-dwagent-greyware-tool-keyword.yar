rule rule_dwagent_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dwagent' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dwagent"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_dwagent_greyware_tool_keyword = /\/dwagent\.desktop/
                        $string2_dwagent_greyware_tool_keyword = /\/dwagent\.service/
                        $string3_dwagent_greyware_tool_keyword = "/dwagsystray"
                        $string4_dwagent_greyware_tool_keyword = /\\\.dwagent\\/ nocase ascii wide
                        $string5_dwagent_greyware_tool_keyword = /\\AppData\\Local\\Temp\\dwagent/ nocase ascii wide
                        $string6_dwagent_greyware_tool_keyword = /\\CurrentVersion\\Run\\DWAgentMon/ nocase ascii wide
                        $string7_dwagent_greyware_tool_keyword = /\\dwagent\.exe/ nocase ascii wide
                        $string8_dwagent_greyware_tool_keyword = /\\DWAgent\.lnk/ nocase ascii wide
                        $string9_dwagent_greyware_tool_keyword = /\\dwagent\.log/ nocase ascii wide
                        $string10_dwagent_greyware_tool_keyword = /\\dwagent\.pid/ nocase ascii wide
                        $string11_dwagent_greyware_tool_keyword = /\\dwagent\.start/ nocase ascii wide
                        $string12_dwagent_greyware_tool_keyword = /\\dwagent\.stop/ nocase ascii wide
                        $string13_dwagent_greyware_tool_keyword = /\\dwaggdi\.dll/ nocase ascii wide
                        $string14_dwagent_greyware_tool_keyword = /\\dwaginstall\.log/ nocase ascii wide
                        $string15_dwagent_greyware_tool_keyword = /\\dwaglnc\.exe/ nocase ascii wide
                        $string16_dwagent_greyware_tool_keyword = /\\dwagsvc\.exe/ nocase ascii wide
                        $string17_dwagent_greyware_tool_keyword = /\\dwagupd\.dll/ nocase ascii wide
                        $string18_dwagent_greyware_tool_keyword = /\\Services\\DWAgent/ nocase ascii wide
                        $string19_dwagent_greyware_tool_keyword = /\\Start\sMenu\\Programs\\DWAgent/ nocase ascii wide
                        $string20_dwagent_greyware_tool_keyword = ">DWAgent<" nocase ascii wide
                        $string21_dwagent_greyware_tool_keyword = "015774ac49fa929ca39c0707aa8177e4605b7df9f53d8630fea1ef5155bb5328" nocase ascii wide
                        $string22_dwagent_greyware_tool_keyword = "1429e62855ce5572b735fe0460ffa6a8f26d56199a8e166152252c7bd659d275" nocase ascii wide
                        $string23_dwagent_greyware_tool_keyword = "3241d780f32a6a89d3b3f30d85f21f33f9d4d91227d129b2fd81d75baa870337" nocase ascii wide
                        $string24_dwagent_greyware_tool_keyword = "36a7532a957652a55dbf0b196905652a1f0b8c4019b7ca4e749fa81e5f2c149b" nocase ascii wide
                        $string25_dwagent_greyware_tool_keyword = "4f21a1d0e7caa97018e4d0b8c7e63fbc54d081976dfda9409f57a3ead24074a7" nocase ascii wide
                        $string26_dwagent_greyware_tool_keyword = "cd12e8a285c77102487f04726b91bc649f9ad087a1e9a5546124a0cc7480c221" nocase ascii wide
                        $string27_dwagent_greyware_tool_keyword = "d2b2455b755476d0b35c721ccdb84432e51812ab646a9210137c1e85b90d7de4" nocase ascii wide
                        $string28_dwagent_greyware_tool_keyword = /dwagent_install\.log/ nocase ascii wide
                        $string29_dwagent_greyware_tool_keyword = /dwagent_unistall\.log/ nocase ascii wide
                        $string30_dwagent_greyware_tool_keyword = /dwaggdi_x86_32\.dll/ nocase ascii wide
                        $string31_dwagent_greyware_tool_keyword = /dwaggdi_x86_64\.dll/ nocase ascii wide
                        $string32_dwagent_greyware_tool_keyword = /dwagscreencapture\.dll/ nocase ascii wide
                        $string33_dwagent_greyware_tool_keyword = /dwagscreencapturebitblt\.dll/ nocase ascii wide
                        $string34_dwagent_greyware_tool_keyword = /dwagscreencapturedesktopduplication\.dll/ nocase ascii wide
                        $string35_dwagent_greyware_tool_keyword = "dwservice/agent" nocase ascii wide
                        $string36_dwagent_greyware_tool_keyword = /Program\sFiles\\DWAgent/ nocase ascii wide
                        $string37_dwagent_greyware_tool_keyword = /www\.dwservice\.net/ nocase ascii wide
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