rule rule_linux_smart_enumeration_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'linux-smart-enumeration' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linux-smart-enumeration"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_linux_smart_enumeration_offensive_tool_keyword = /\s\$lse_find_opts\s/
                        $string2_linux_smart_enumeration_offensive_tool_keyword = /\.\/lse\.sh/
                        $string3_linux_smart_enumeration_offensive_tool_keyword = /\/etc\/passwd.{0,1000}\/\.sudo_as_admin_successful/
                        $string4_linux_smart_enumeration_offensive_tool_keyword = /\/linux\-smart\-enumeration\.git/
                        $string5_linux_smart_enumeration_offensive_tool_keyword = /\/releases\/latest\/download\/lse\.sh/
                        $string6_linux_smart_enumeration_offensive_tool_keyword = /adm\|admin\|root\|sudo\|wheel/
                        $string7_linux_smart_enumeration_offensive_tool_keyword = /bash\slse\.sh/
                        $string8_linux_smart_enumeration_offensive_tool_keyword = /chmod\s700\slse\.sh/
                        $string9_linux_smart_enumeration_offensive_tool_keyword = /chmod\s755\slse\.sh/
                        $string10_linux_smart_enumeration_offensive_tool_keyword = "diego-treitos/linux-smart-enumeration"
                        $string11_linux_smart_enumeration_offensive_tool_keyword = /find\s\/\s.{0,1000}\s\-4000\s\-type\sf\s\-print/
                        $string12_linux_smart_enumeration_offensive_tool_keyword = /find\s\/\s.{0,1000}\s\-perm\s\-2000\s\-type\sf\s\-print/
                        $string13_linux_smart_enumeration_offensive_tool_keyword = /find\s\/\s.{0,1000}\s\-regextype\segrep\s\-iregex.{0,1000}\\\.kdbx/
                        $string14_linux_smart_enumeration_offensive_tool_keyword = /https\:\/\/.{0,1000}\/releases\/download\/.{0,1000}\/lse\.sh/
                        $string15_linux_smart_enumeration_offensive_tool_keyword = "linux-smart-enumeration-master"
                        $string16_linux_smart_enumeration_offensive_tool_keyword = /lse\.sh\s\-l/
                        $string17_linux_smart_enumeration_offensive_tool_keyword = /netstat\s\-tnlp\s\|\|\sss\s\-tnlp/
                        $string18_linux_smart_enumeration_offensive_tool_keyword = /netstat\s\-unlp\s\|\|\sss\s\-unlp/
                        $string19_linux_smart_enumeration_offensive_tool_keyword = /package_cvs_into_lse\.sh/
                        $string20_linux_smart_enumeration_offensive_tool_keyword = /ss\s\-tunlp\s\|\|\snetstat\s\-tunlp.{0,1000}127\.0\.0\.1/
                        $string21_linux_smart_enumeration_offensive_tool_keyword = "sudo -nS id' && lse_sudo=true"
                        $string22_linux_smart_enumeration_offensive_tool_keyword = /user\|username\|login\|pass\|password\|pw\|credentials/

    condition:
        any of them
}