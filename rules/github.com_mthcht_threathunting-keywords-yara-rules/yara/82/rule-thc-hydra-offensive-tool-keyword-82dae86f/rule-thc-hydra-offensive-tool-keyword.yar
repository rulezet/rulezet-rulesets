rule rule_thc_hydra_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'thc-hydra' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "thc-hydra"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_thc_hydra_offensive_tool_keyword = /\sdefault_logins\.txt/
                        $string2_thc_hydra_offensive_tool_keyword = " thc-hidra"
                        $string3_thc_hydra_offensive_tool_keyword = /\.\/hydra\s/
                        $string4_thc_hydra_offensive_tool_keyword = /\.\/xhydra/
                        $string5_thc_hydra_offensive_tool_keyword = "/hydra -"
                        $string6_thc_hydra_offensive_tool_keyword = "/thc-hydra/"
                        $string7_thc_hydra_offensive_tool_keyword = /common_passwords\.txt/
                        $string8_thc_hydra_offensive_tool_keyword = "dpl4hydra "
                        $string9_thc_hydra_offensive_tool_keyword = /dpl4hydra\.sh/
                        $string10_thc_hydra_offensive_tool_keyword = /dpl4hydra_.{0,1000}\.csv/
                        $string11_thc_hydra_offensive_tool_keyword = /dpl4hydra_.{0,1000}\.tmp/
                        $string12_thc_hydra_offensive_tool_keyword = "dpl4hydra_linksys"
                        $string13_thc_hydra_offensive_tool_keyword = /hydra\s.{0,1000}\sftp\:\/\//
                        $string14_thc_hydra_offensive_tool_keyword = /hydra\s.{0,1000}\shttp\-post\-form\s/
                        $string15_thc_hydra_offensive_tool_keyword = /hydra\s.{0,1000}\smysql\:\/\//
                        $string16_thc_hydra_offensive_tool_keyword = /hydra\s.{0,1000}\sssh\:\/\//
                        $string17_thc_hydra_offensive_tool_keyword = /hydra\s.{0,1000}\stelnet\:\/\//
                        $string18_thc_hydra_offensive_tool_keyword = "hydra smtp-enum"
                        $string19_thc_hydra_offensive_tool_keyword = "hydra:x:10001:"
                        $string20_thc_hydra_offensive_tool_keyword = "HYDRA_PROXY_HTTP"
                        $string21_thc_hydra_offensive_tool_keyword = "hydra-cobaltstrike"
                        $string22_thc_hydra_offensive_tool_keyword = "install hydra-gtk"
                        $string23_thc_hydra_offensive_tool_keyword = "pw-inspector -"
                        $string24_thc_hydra_offensive_tool_keyword = /pw\-inspector\./
                        $string25_thc_hydra_offensive_tool_keyword = "thc-hydra"
                        $string26_thc_hydra_offensive_tool_keyword = /thc\-hydra\.git/
                        $string27_thc_hydra_offensive_tool_keyword = /thc\-hydra\.git/
                        $string28_thc_hydra_offensive_tool_keyword = "vanhauser-thc/thc-hydra"
                        $string29_thc_hydra_offensive_tool_keyword = "hydra -"

    condition:
        any of them
}