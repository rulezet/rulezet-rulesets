rule rule_IIS_Raid_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'IIS-Raid' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IIS-Raid"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_IIS_Raid_offensive_tool_keyword = /\siis_controller\.py/ nocase ascii wide
                        $string2_IIS_Raid_offensive_tool_keyword = " --url --password SIMPLEPASS" nocase ascii wide
                        $string3_IIS_Raid_offensive_tool_keyword = /\/iis_controller\.py/ nocase ascii wide
                        $string4_IIS_Raid_offensive_tool_keyword = /\/IIS\-Raid\.git/ nocase ascii wide
                        $string5_IIS_Raid_offensive_tool_keyword = /\[\+\]\sShellcode\sInjected\sSuccessfully/ nocase ascii wide
                        $string6_IIS_Raid_offensive_tool_keyword = /\\iis_controller\.py/ nocase ascii wide
                        $string7_IIS_Raid_offensive_tool_keyword = /\\Windows\\Temp\\creds\.db/ nocase ascii wide
                        $string8_IIS_Raid_offensive_tool_keyword = "0x09AL/IIS-Raid" nocase ascii wide
                        $string9_IIS_Raid_offensive_tool_keyword = "B5E39D15-9678-474A-9838-4C720243968B" nocase ascii wide
                        $string10_IIS_Raid_offensive_tool_keyword = /IIS\-Backdoor\./ nocase ascii wide
                        $string11_IIS_Raid_offensive_tool_keyword = "IIS-Raid-master" nocase ascii wide
                        $string12_IIS_Raid_offensive_tool_keyword = /Inject\sshellcode\son\sthe\sserver\.\\\\nUsage\:\sinject/ nocase ascii wide
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