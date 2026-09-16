rule rule_WindowsDowndate_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WindowsDowndate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WindowsDowndate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WindowsDowndate_offensive_tool_keyword = /\swindows_downdate\.py/ nocase ascii wide
                        $string2_WindowsDowndate_offensive_tool_keyword = /\/windows_downdate\.py/ nocase ascii wide
                        $string3_WindowsDowndate_offensive_tool_keyword = /\/WindowsDowndate\.git/ nocase ascii wide
                        $string4_WindowsDowndate_offensive_tool_keyword = /\\windows_downdate\.py/ nocase ascii wide
                        $string5_WindowsDowndate_offensive_tool_keyword = /\\WindowsDowndate\-main/ nocase ascii wide
                        $string6_WindowsDowndate_offensive_tool_keyword = "0a0be178cd014f569eac8697ce355c7ceb59b7e1a3aaa18673a7ffde4a044c88" nocase ascii wide
                        $string7_WindowsDowndate_offensive_tool_keyword = "50eb54d0976374701c6051c23b993708,4d67d3d82b1adcc1b96e743e9b0efaaa8a566e3d,a34e71ededf334d3d6a480e3738c91fccbb4d2c1fbeec7192db9793a2541e8ca" nocase ascii wide
                        $string8_WindowsDowndate_offensive_tool_keyword = /CVE\-2021\-27090\-Secure\-Kernel\-EoP\-Patch\-Downgrade\/Config\.xml/ nocase ascii wide
                        $string9_WindowsDowndate_offensive_tool_keyword = /CVE\-2022\-34709\-Credential\-Guard\-EoP\-Patch\-Downgrade\/Config\.xml/ nocase ascii wide
                        $string10_WindowsDowndate_offensive_tool_keyword = /CVE\-2023\-21768\-AFD\-Driver\-EoP\-Patch\-Downgrade\/Config\.xml/ nocase ascii wide
                        $string11_WindowsDowndate_offensive_tool_keyword = "dab858feab4506727059fda4645865e2029892c6560704a7077433bab5d5ca0e" nocase ascii wide
                        $string12_WindowsDowndate_offensive_tool_keyword = /from\swindows_downdate\./ nocase ascii wide
                        $string13_WindowsDowndate_offensive_tool_keyword = /Hyper\-V\-Hypervisor\-Downgrade\/Config\.xml/ nocase ascii wide
                        $string14_WindowsDowndate_offensive_tool_keyword = /Kernel\-Suite\-Downgrade\/Config\.xml/ nocase ascii wide
                        $string15_WindowsDowndate_offensive_tool_keyword = /PPLFault\-Patch\-Downgrade\/Config\.xml/ nocase ascii wide
                        $string16_WindowsDowndate_offensive_tool_keyword = "SafeBreach-Labs/WindowsDowndate" nocase ascii wide
                        $string17_WindowsDowndate_offensive_tool_keyword = "Starting Windows-Downdate" nocase ascii wide
                        $string18_WindowsDowndate_offensive_tool_keyword = /VBS\-UEFI\-Locks\-Bypass\/Config\.xml/ nocase ascii wide
                        $string19_WindowsDowndate_offensive_tool_keyword = "Windows Downdate: Craft any downgrading Windows Updates" nocase ascii wide
                        $string20_WindowsDowndate_offensive_tool_keyword = /windows_downdate\.exe/ nocase ascii wide
                        $string21_WindowsDowndate_offensive_tool_keyword = "Windows-Downdate must be run as an Administrator" nocase ascii wide
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