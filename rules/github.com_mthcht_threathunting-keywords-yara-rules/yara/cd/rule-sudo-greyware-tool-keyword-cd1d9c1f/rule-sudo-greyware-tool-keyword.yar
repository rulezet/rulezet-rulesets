rule rule_sudo_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sudo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sudo"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_sudo_greyware_tool_keyword = /\.server_DoElevationRequest\(\(Get\-NtProcess\s\-ProcessId\s\$pid\).{0,1000}\\"cmd\.exe\\".{0,1000}C\:\\\\"/
                        $string2_sudo_greyware_tool_keyword = /Connect\-RpcClient\s.{0,1000}\s\-EndpointPath\ssudo_elevate_4652/
                        $string3_sudo_greyware_tool_keyword = /echo\s.{0,1000}\%sudo\s\sALL\=\(ALL\)\sNOPASSWD\:\sALL.{0,1000}\s\>\>\s\/etc\/sudoers/
                        $string4_sudo_greyware_tool_keyword = "sudo apache2 -f /etc/shadow"
                        $string5_sudo_greyware_tool_keyword = /sudo\sLD_LIBRARY_PATH\=\.\sapache2/
                        $string6_sudo_greyware_tool_keyword = /sudo\sLD_PRELOAD\=\/tmp\/preload\.so\sfind/
                        $string7_sudo_greyware_tool_keyword = "sudo log erase --all"

    condition:
        any of them
}