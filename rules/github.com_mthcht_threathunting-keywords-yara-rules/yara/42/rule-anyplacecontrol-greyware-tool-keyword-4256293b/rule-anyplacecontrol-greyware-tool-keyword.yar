rule rule_AnyplaceControl_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AnyplaceControl' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AnyplaceControl"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_AnyplaceControl_greyware_tool_keyword = /\/anyplace\-control\/data2\/.{0,100}\.exe/ nocase ascii wide
                        $string2_AnyplaceControl_greyware_tool_keyword = /\\Anyplace\sControl\s\-\sAdmin\.lnk/ nocase ascii wide
                        $string3_AnyplaceControl_greyware_tool_keyword = /\\Anyplace\sControl\\/ nocase ascii wide
                        $string4_AnyplaceControl_greyware_tool_keyword = /\\anyplace\-control\.ini/ nocase ascii wide
                        $string5_AnyplaceControl_greyware_tool_keyword = /\\AppData\\Local\\Temp\\.{0,100}\\zmstage\.exe/ nocase ascii wide
                        $string6_AnyplaceControl_greyware_tool_keyword = /\\AppData\\Roaming\\Anyplace\sControl/ nocase ascii wide
                        $string7_AnyplaceControl_greyware_tool_keyword = /\\Program\sFiles\s\(x86\)\\Anyplace\sControl/ nocase ascii wide
                        $string8_AnyplaceControl_greyware_tool_keyword = /\\ProgramData\\Anyplace\sControl\s/ nocase ascii wide
                        $string9_AnyplaceControl_greyware_tool_keyword = ">Anyplace Control Software<" nocase ascii wide
                        $string10_AnyplaceControl_greyware_tool_keyword = "a2fa034d006bdbc3ee2a15e55eb647f8097355c288a858da1e309fe8ac1cf0a3" nocase ascii wide
                        $string11_AnyplaceControl_greyware_tool_keyword = /AnyplaceControlInstall\.exe/ nocase ascii wide
                        $string12_AnyplaceControl_greyware_tool_keyword = /Program\sFiles\s\(x86\)\\Anyplace\sControl/ nocase ascii wide
                        $string13_AnyplaceControl_greyware_tool_keyword = /www\.anyplace\-control\.com\/install/ nocase ascii wide
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