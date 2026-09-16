rule sudo
{
    meta:
        description = "Detection patterns for the tool 'sudo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sudo"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.server_DoElevationRequest\(\(Get\-NtProcess\s\-ProcessId\s\$pid\).{0,1000}\\"cmd\.exe\\".{0,1000}C\:\\\\"/
                        $string2 = /Connect\-RpcClient\s.{0,1000}\s\-EndpointPath\ssudo_elevate_4652/
                        $string3 = /echo\s.{0,1000}\%sudo\s\sALL\=\(ALL\)\sNOPASSWD\:\sALL.{0,1000}\s\>\>\s\/etc\/sudoers/
                        $string4 = "sudo apache2 -f /etc/shadow"
                        $string5 = /sudo\sLD_LIBRARY_PATH\=\.\sapache2/
                        $string6 = /sudo\sLD_PRELOAD\=\/tmp\/preload\.so\sfind/
                        $string7 = "sudo log erase --all"

    condition:
        any of them
}