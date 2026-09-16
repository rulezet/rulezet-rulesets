rule rule_SharpStay_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpStay' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpStay"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpStay_offensive_tool_keyword = " action=BackdoorLNK " nocase ascii wide
                        $string2_SharpStay_offensive_tool_keyword = /\saction\=CreateService\sservicename\=.{0,100}\scommand\=/ nocase ascii wide
                        $string3_SharpStay_offensive_tool_keyword = " action=ElevatedRegistryKey keyname=Debug keypath" nocase ascii wide
                        $string4_SharpStay_offensive_tool_keyword = " action=ElevatedUserInitKey command=" nocase ascii wide
                        $string5_SharpStay_offensive_tool_keyword = /\saction\=JunctionFolder\sdllpath\=.{0,100}\.dll\sguid\=/ nocase ascii wide
                        $string6_SharpStay_offensive_tool_keyword = /\saction\=NewLNK\sfilepath\=.{0,100}\\"\slnkname\=/ nocase ascii wide
                        $string7_SharpStay_offensive_tool_keyword = /\saction\=ScheduledTask\staskname\=.{0,100}\scommand\=.{0,100}runasuser/ nocase ascii wide
                        $string8_SharpStay_offensive_tool_keyword = /\saction\=ScheduledTaskAction\staskname\=.{0,100}\scommand\=/ nocase ascii wide
                        $string9_SharpStay_offensive_tool_keyword = " action=SchTaskCOMHijack clsid=" nocase ascii wide
                        $string10_SharpStay_offensive_tool_keyword = " action=UserRegistryKey keyname=Debug keypath=HKCU:" nocase ascii wide
                        $string11_SharpStay_offensive_tool_keyword = /\saction\=WMIEventSub\scommand\=.{0,100}\seventname\=/ nocase ascii wide
                        $string12_SharpStay_offensive_tool_keyword = /\.exe\saction\=GetScheduledTaskCOMHandler/ nocase ascii wide
                        $string13_SharpStay_offensive_tool_keyword = /\.exe\saction\=ListRunningServices/ nocase ascii wide
                        $string14_SharpStay_offensive_tool_keyword = /\.exe\saction\=ListScheduledTasks/ nocase ascii wide
                        $string15_SharpStay_offensive_tool_keyword = /\.exe\saction\=ListTaskNames/ nocase ascii wide
                        $string16_SharpStay_offensive_tool_keyword = "/0xthirteen/" nocase ascii wide
                        $string17_SharpStay_offensive_tool_keyword = /\/SharpStay\.git/ nocase ascii wide
                        $string18_SharpStay_offensive_tool_keyword = "/SharpStay/" nocase ascii wide
                        $string19_SharpStay_offensive_tool_keyword = /\[\+\]\sCreated\sElevated\sHKLM\:/ nocase ascii wide
                        $string20_SharpStay_offensive_tool_keyword = /\[\+\]\sUpdated\sElevated\sHKLM\:Software\\\\Microsoft\\\\Windows\sNT\\\\CurrentVersion\\\\Winlogon\skey\sUserInit/ nocase ascii wide
                        $string21_SharpStay_offensive_tool_keyword = "0xthirteen/SharpStay" nocase ascii wide
                        $string22_SharpStay_offensive_tool_keyword = "2963C954-7B1E-47F5-B4FA-2FC1F0D56AEA" nocase ascii wide
                        $string23_SharpStay_offensive_tool_keyword = "2963C954-7B1E-47F5-B4FA-2FC1F0D56AEA" nocase ascii wide
                        $string24_SharpStay_offensive_tool_keyword = "action=SchTaskCOMHijack " nocase ascii wide
                        $string25_SharpStay_offensive_tool_keyword = /SharpStay\.csproj/ nocase ascii wide
                        $string26_SharpStay_offensive_tool_keyword = /Sharpstay\.exe/ nocase ascii wide
                        $string27_SharpStay_offensive_tool_keyword = /SharpStay\.sln/ nocase ascii wide
                        $string28_SharpStay_offensive_tool_keyword = "SharpStay-master" nocase ascii wide
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