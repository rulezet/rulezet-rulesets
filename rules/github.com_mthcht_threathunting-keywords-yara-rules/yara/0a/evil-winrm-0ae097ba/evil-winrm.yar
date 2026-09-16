rule evil_winrm
{
    meta:
        description = "Detection patterns for the tool 'evil-winrm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evil-winrm"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdownload\s.{0,1000}\\NTDS\\NTDS\.dit/ nocase ascii wide
                        $string2 = /\sdownload\s.{0,1000}\\Windows\\System32\\config\\SYSTEM/ nocase ascii wide
                        $string3 = "Bypass-4MSI" nocase ascii wide
                        $string4 = /cmd\s\/c\smklink\s\/d\s.{0,1000}\sHarddiskVolumeShadowCopy1/ nocase ascii wide
                        $string5 = "Dll-Loader -http -path " nocase ascii wide
                        $string6 = "Dll-Loader -local -path" nocase ascii wide
                        $string7 = "Dll-Loader -smb -path " nocase ascii wide
                        $string8 = "Donut-Loader -process_id" nocase ascii wide
                        $string9 = /donut\-maker\.py\s\-i\s.{0,1000}\.exe/ nocase ascii wide
                        $string10 = /download\s.{0,1000}Roaming\\mRemoteNG\\confCons\.xml/ nocase ascii wide
                        $string11 = "evil-winrm" nocase ascii wide
                        $string12 = /Invoke\-Binary\s.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}