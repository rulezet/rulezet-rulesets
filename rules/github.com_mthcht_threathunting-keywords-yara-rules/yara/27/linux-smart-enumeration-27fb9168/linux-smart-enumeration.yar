rule linux_smart_enumeration
{
    meta:
        description = "Detection patterns for the tool 'linux-smart-enumeration' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linux-smart-enumeration"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\$lse_find_opts\s/
                        $string2 = /\.\/lse\.sh/
                        $string3 = /\/etc\/passwd.{0,1000}\/\.sudo_as_admin_successful/
                        $string4 = /\/linux\-smart\-enumeration\.git/
                        $string5 = /\/releases\/latest\/download\/lse\.sh/
                        $string6 = /adm\|admin\|root\|sudo\|wheel/
                        $string7 = /bash\slse\.sh/
                        $string8 = /chmod\s700\slse\.sh/
                        $string9 = /chmod\s755\slse\.sh/
                        $string10 = "diego-treitos/linux-smart-enumeration"
                        $string11 = /find\s\/\s.{0,1000}\s\-4000\s\-type\sf\s\-print/
                        $string12 = /find\s\/\s.{0,1000}\s\-perm\s\-2000\s\-type\sf\s\-print/
                        $string13 = /find\s\/\s.{0,1000}\s\-regextype\segrep\s\-iregex.{0,1000}\\\.kdbx/
                        $string14 = /https\:\/\/.{0,1000}\/releases\/download\/.{0,1000}\/lse\.sh/
                        $string15 = "linux-smart-enumeration-master"
                        $string16 = /lse\.sh\s\-l/
                        $string17 = /netstat\s\-tnlp\s\|\|\sss\s\-tnlp/
                        $string18 = /netstat\s\-unlp\s\|\|\sss\s\-unlp/
                        $string19 = /package_cvs_into_lse\.sh/
                        $string20 = /ss\s\-tunlp\s\|\|\snetstat\s\-tunlp.{0,1000}127\.0\.0\.1/
                        $string21 = "sudo -nS id' && lse_sudo=true"
                        $string22 = /user\|username\|login\|pass\|password\|pw\|credentials/

    condition:
        any of them
}