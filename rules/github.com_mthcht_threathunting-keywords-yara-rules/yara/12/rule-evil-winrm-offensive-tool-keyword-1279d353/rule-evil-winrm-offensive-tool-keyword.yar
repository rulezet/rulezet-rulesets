rule rule_evil_winrm_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'evil-winrm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evil-winrm"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_evil_winrm_offensive_tool_keyword = /\sdownload\s.{0,1000}\\NTDS\\NTDS\.dit/ nocase ascii wide
                        $string2_evil_winrm_offensive_tool_keyword = /\sdownload\s.{0,1000}\\Windows\\System32\\config\\SYSTEM/ nocase ascii wide
                        $string3_evil_winrm_offensive_tool_keyword = "Bypass-4MSI" nocase ascii wide
                        $string4_evil_winrm_offensive_tool_keyword = /cmd\s\/c\smklink\s\/d\s.{0,1000}\sHarddiskVolumeShadowCopy1/ nocase ascii wide
                        $string5_evil_winrm_offensive_tool_keyword = "Dll-Loader -http -path " nocase ascii wide
                        $string6_evil_winrm_offensive_tool_keyword = "Dll-Loader -local -path" nocase ascii wide
                        $string7_evil_winrm_offensive_tool_keyword = "Dll-Loader -smb -path " nocase ascii wide
                        $string8_evil_winrm_offensive_tool_keyword = "Donut-Loader -process_id" nocase ascii wide
                        $string9_evil_winrm_offensive_tool_keyword = /donut\-maker\.py\s\-i\s.{0,1000}\.exe/ nocase ascii wide
                        $string10_evil_winrm_offensive_tool_keyword = /download\s.{0,1000}Roaming\\mRemoteNG\\confCons\.xml/ nocase ascii wide
                        $string11_evil_winrm_offensive_tool_keyword = "evil-winrm" nocase ascii wide
                        $string12_evil_winrm_offensive_tool_keyword = /Invoke\-Binary\s.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}