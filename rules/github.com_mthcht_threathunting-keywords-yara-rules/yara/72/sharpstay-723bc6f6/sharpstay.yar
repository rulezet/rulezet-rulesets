rule SharpStay
{
    meta:
        description = "Detection patterns for the tool 'SharpStay' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpStay"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " action=BackdoorLNK " nocase ascii wide
                        $string2 = /\saction\=CreateService\sservicename\=.{0,1000}\scommand\=/ nocase ascii wide
                        $string3 = " action=ElevatedRegistryKey keyname=Debug keypath" nocase ascii wide
                        $string4 = " action=ElevatedUserInitKey command=" nocase ascii wide
                        $string5 = /\saction\=JunctionFolder\sdllpath\=.{0,1000}\.dll\sguid\=/ nocase ascii wide
                        $string6 = /\saction\=NewLNK\sfilepath\=.{0,1000}\\"\slnkname\=/ nocase ascii wide
                        $string7 = /\saction\=ScheduledTask\staskname\=.{0,1000}\scommand\=.{0,1000}runasuser/ nocase ascii wide
                        $string8 = /\saction\=ScheduledTaskAction\staskname\=.{0,1000}\scommand\=/ nocase ascii wide
                        $string9 = " action=SchTaskCOMHijack clsid=" nocase ascii wide
                        $string10 = " action=UserRegistryKey keyname=Debug keypath=HKCU:" nocase ascii wide
                        $string11 = /\saction\=WMIEventSub\scommand\=.{0,1000}\seventname\=/ nocase ascii wide
                        $string12 = /\.exe\saction\=GetScheduledTaskCOMHandler/ nocase ascii wide
                        $string13 = /\.exe\saction\=ListRunningServices/ nocase ascii wide
                        $string14 = /\.exe\saction\=ListScheduledTasks/ nocase ascii wide
                        $string15 = /\.exe\saction\=ListTaskNames/ nocase ascii wide
                        $string16 = "/0xthirteen/" nocase ascii wide
                        $string17 = /\/SharpStay\.git/ nocase ascii wide
                        $string18 = "/SharpStay/" nocase ascii wide
                        $string19 = /\[\+\]\sCreated\sElevated\sHKLM\:/ nocase ascii wide
                        $string20 = /\[\+\]\sUpdated\sElevated\sHKLM\:Software\\\\Microsoft\\\\Windows\sNT\\\\CurrentVersion\\\\Winlogon\skey\sUserInit/ nocase ascii wide
                        $string21 = "0xthirteen/SharpStay" nocase ascii wide
                        $string22 = "2963C954-7B1E-47F5-B4FA-2FC1F0D56AEA" nocase ascii wide
                        $string23 = "2963C954-7B1E-47F5-B4FA-2FC1F0D56AEA" nocase ascii wide
                        $string24 = "action=SchTaskCOMHijack " nocase ascii wide
                        $string25 = /SharpStay\.csproj/ nocase ascii wide
                        $string26 = /Sharpstay\.exe/ nocase ascii wide
                        $string27 = /SharpStay\.sln/ nocase ascii wide
                        $string28 = "SharpStay-master" nocase ascii wide

    condition:
        any of them
}