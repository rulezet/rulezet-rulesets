rule rule_veeam_creds_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'veeam-creds' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "veeam-creds"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_veeam_creds_offensive_tool_keyword = /\$VeaamRegPath.{0,1000}SqlDatabaseName/ nocase ascii wide
                        $string2_veeam_creds_offensive_tool_keyword = /\$VeaamRegPath.{0,1000}SqlInstanceName/ nocase ascii wide
                        $string3_veeam_creds_offensive_tool_keyword = /\$VeaamRegPath.{0,1000}SqlServerName/ nocase ascii wide
                        $string4_veeam_creds_offensive_tool_keyword = /\/veeam\-creds\.git/ nocase ascii wide
                        $string5_veeam_creds_offensive_tool_keyword = /\\veeam\-creds\\/ nocase ascii wide
                        $string6_veeam_creds_offensive_tool_keyword = "4d9b2297358dbe1d72168480ab67ef7b992c2b84d4f09d71d906c941523f7b74" nocase ascii wide
                        $string7_veeam_creds_offensive_tool_keyword = "5c7e09b63bd99851d8b93241f3907917c07af3903aa024da0bd549ae1fc373f7" nocase ascii wide
                        $string8_veeam_creds_offensive_tool_keyword = "b683f658cc3320b969164f1dd01ce028c2a2e8f69ed56695415805cb601b96cc" nocase ascii wide
                        $string9_veeam_creds_offensive_tool_keyword = "b683f658cc3320b969164f1dd01ce028c2a2e8f69ed56695415805cb601b96cc" nocase ascii wide
                        $string10_veeam_creds_offensive_tool_keyword = "dd05c2d2a5d00de8f4ef3dd6d8e2304d2ecb3787e97edd0e38867d047b0936a0" nocase ascii wide
                        $string11_veeam_creds_offensive_tool_keyword = "Here are some passwords for you, have fun:" nocase ascii wide
                        $string12_veeam_creds_offensive_tool_keyword = "Invoke-VeeamGetCreds" nocase ascii wide
                        $string13_veeam_creds_offensive_tool_keyword = "sadshade/veeam-creds" nocase ascii wide
                        $string14_veeam_creds_offensive_tool_keyword = "veeam-creds-main" nocase ascii wide
                        $string15_veeam_creds_offensive_tool_keyword = /Veeam\-Get\-Creds\.ps1/ nocase ascii wide
                        $string16_veeam_creds_offensive_tool_keyword = /VeeamGetCreds\.yaml/ nocase ascii wide
                        $string17_veeam_creds_offensive_tool_keyword = /veeampot\.py/ nocase ascii wide

    condition:
        any of them
}