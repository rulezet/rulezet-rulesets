rule rule_linux_pam_backdoor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'linux-pam-backdoor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linux-pam-backdoor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_linux_pam_backdoor_offensive_tool_keyword = /\.\/backdoor\.sh\s/
                        $string2_linux_pam_backdoor_offensive_tool_keyword = /\/linux\-pam\-backdoor\.git/
                        $string3_linux_pam_backdoor_offensive_tool_keyword = /backdoor\.sh\s\-v\s.{0,1000}\s\-p\s/
                        $string4_linux_pam_backdoor_offensive_tool_keyword = "linux-pam-backdoor-master"
                        $string5_linux_pam_backdoor_offensive_tool_keyword = "zephrax/linux-pam-backdoor"

    condition:
        any of them
}