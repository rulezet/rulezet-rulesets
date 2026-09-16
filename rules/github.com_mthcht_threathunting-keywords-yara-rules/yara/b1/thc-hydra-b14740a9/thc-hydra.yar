rule thc_hydra
{
    meta:
        description = "Detection patterns for the tool 'thc-hydra' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "thc-hydra"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdefault_logins\.txt/
                        $string2 = " thc-hidra"
                        $string3 = /\.\/hydra\s/
                        $string4 = /\.\/xhydra/
                        $string5 = "/hydra -"
                        $string6 = "/thc-hydra/"
                        $string7 = /common_passwords\.txt/
                        $string8 = "dpl4hydra "
                        $string9 = /dpl4hydra\.sh/
                        $string10 = /dpl4hydra_.{0,1000}\.csv/
                        $string11 = /dpl4hydra_.{0,1000}\.tmp/
                        $string12 = "dpl4hydra_linksys"
                        $string13 = /hydra\s.{0,1000}\sftp\:\/\//
                        $string14 = /hydra\s.{0,1000}\shttp\-post\-form\s/
                        $string15 = /hydra\s.{0,1000}\smysql\:\/\//
                        $string16 = /hydra\s.{0,1000}\sssh\:\/\//
                        $string17 = /hydra\s.{0,1000}\stelnet\:\/\//
                        $string18 = "hydra smtp-enum"
                        $string19 = "hydra:x:10001:"
                        $string20 = "HYDRA_PROXY_HTTP"
                        $string21 = "hydra-cobaltstrike"
                        $string22 = "install hydra-gtk"
                        $string23 = "pw-inspector -"
                        $string24 = /pw\-inspector\./
                        $string25 = "thc-hydra"
                        $string26 = /thc\-hydra\.git/
                        $string27 = /thc\-hydra\.git/
                        $string28 = "vanhauser-thc/thc-hydra"
                        $string29 = "hydra -"

    condition:
        any of them
}