rule veeam_creds
{
    meta:
        description = "Detection patterns for the tool 'veeam-creds' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "veeam-creds"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\$VeaamRegPath.{0,1000}SqlDatabaseName/ nocase ascii wide
                        $string2 = /\$VeaamRegPath.{0,1000}SqlInstanceName/ nocase ascii wide
                        $string3 = /\$VeaamRegPath.{0,1000}SqlServerName/ nocase ascii wide
                        $string4 = /\/veeam\-creds\.git/ nocase ascii wide
                        $string5 = /\\veeam\-creds\\/ nocase ascii wide
                        $string6 = "4d9b2297358dbe1d72168480ab67ef7b992c2b84d4f09d71d906c941523f7b74" nocase ascii wide
                        $string7 = "5c7e09b63bd99851d8b93241f3907917c07af3903aa024da0bd549ae1fc373f7" nocase ascii wide
                        $string8 = "b683f658cc3320b969164f1dd01ce028c2a2e8f69ed56695415805cb601b96cc" nocase ascii wide
                        $string9 = "b683f658cc3320b969164f1dd01ce028c2a2e8f69ed56695415805cb601b96cc" nocase ascii wide
                        $string10 = "dd05c2d2a5d00de8f4ef3dd6d8e2304d2ecb3787e97edd0e38867d047b0936a0" nocase ascii wide
                        $string11 = "Here are some passwords for you, have fun:" nocase ascii wide
                        $string12 = "Invoke-VeeamGetCreds" nocase ascii wide
                        $string13 = "sadshade/veeam-creds" nocase ascii wide
                        $string14 = "veeam-creds-main" nocase ascii wide
                        $string15 = /Veeam\-Get\-Creds\.ps1/ nocase ascii wide
                        $string16 = /VeeamGetCreds\.yaml/ nocase ascii wide
                        $string17 = /veeampot\.py/ nocase ascii wide

    condition:
        any of them
}