rule rule_donpapi_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'donpapi' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "donpapi"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_donpapi_offensive_tool_keyword = " run donpapi" nocase ascii wide
                        $string2_donpapi_offensive_tool_keyword = /\.py\s\s\-credz\s.{0,1000}\.txt\s.{0,1000}\s/ nocase ascii wide
                        $string3_donpapi_offensive_tool_keyword = /\/chrome_decrypt\.py/ nocase ascii wide
                        $string4_donpapi_offensive_tool_keyword = "/creddump7/" nocase ascii wide
                        $string5_donpapi_offensive_tool_keyword = /\/DonPAPI\.git/ nocase ascii wide
                        $string6_donpapi_offensive_tool_keyword = /\/DonPAPI\.py/ nocase ascii wide
                        $string7_donpapi_offensive_tool_keyword = /\/firefox_decrypt\.py/ nocase ascii wide
                        $string8_donpapi_offensive_tool_keyword = /\/lastpass\.py/ nocase ascii wide
                        $string9_donpapi_offensive_tool_keyword = "/login-securite/DonPAPI" nocase ascii wide
                        $string10_donpapi_offensive_tool_keyword = "28a2e9e1ab772d0017aa994feae882eeea526fcbcb2f929ec410eabcf2912c14" nocase ascii wide
                        $string11_donpapi_offensive_tool_keyword = "4860280fe3039b1f65dad29dbcbb674c6f41004c34e99d382b824b4004aacdd0" nocase ascii wide
                        $string12_donpapi_offensive_tool_keyword = "9bfad1d826217983cbf0bb46c9578f592002d7893e0e359ef30f888c3693ad3c" nocase ascii wide
                        $string13_donpapi_offensive_tool_keyword = "a2b0e31afa53dfc587fa9e80abddbb6bb01d1050d5e68359f6f298a84fa6625e" nocase ascii wide
                        $string14_donpapi_offensive_tool_keyword = "c1f971aa959ea7722c8bc41a6677ad83230e129d69424c16835c3d000756582e" nocase ascii wide
                        $string15_donpapi_offensive_tool_keyword = "c35aa22a683405cb282d97f125cb785cd7767591c96f4d00a27e5ac92b494f6c" nocase ascii wide
                        $string16_donpapi_offensive_tool_keyword = "Decrypting DPAPI data with masterkey " nocase ascii wide
                        $string17_donpapi_offensive_tool_keyword = /domcachedump\.py/ nocase ascii wide
                        $string18_donpapi_offensive_tool_keyword = "donapapi -pvk " nocase ascii wide
                        $string19_donpapi_offensive_tool_keyword = "donpapi -credz " nocase ascii wide
                        $string20_donpapi_offensive_tool_keyword = /donpapi\.lazagne\.softwares/ nocase ascii wide
                        $string21_donpapi_offensive_tool_keyword = /donpapi\.myseatbelt\'/ nocase ascii wide
                        $string22_donpapi_offensive_tool_keyword = /DonPAPI\.py\s/ nocase ascii wide
                        $string23_donpapi_offensive_tool_keyword = /donpapi\-master\.zip/ nocase ascii wide
                        $string24_donpapi_offensive_tool_keyword = /dpapi_pick\/credhist\.py/ nocase ascii wide
                        $string25_donpapi_offensive_tool_keyword = "dump_CREDENTIAL_MSOFFICE" nocase ascii wide
                        $string26_donpapi_offensive_tool_keyword = /dump_CREDENTIAL_TASKSCHEDULER\(/ nocase ascii wide
                        $string27_donpapi_offensive_tool_keyword = "dump_CREDENTIAL_TASKSCHEDULER" nocase ascii wide
                        $string28_donpapi_offensive_tool_keyword = "dump_CREDENTIAL_TSE" nocase ascii wide
                        $string29_donpapi_offensive_tool_keyword = "dump_VAULT_INTERNET_EXPLORER" nocase ascii wide
                        $string30_donpapi_offensive_tool_keyword = "dump_VAULT_NGC_LOCAL_ACCOOUNT" nocase ascii wide
                        $string31_donpapi_offensive_tool_keyword = "dump_VAULT_WIN_BIO_KEY" nocase ascii wide
                        $string32_donpapi_offensive_tool_keyword = "e292dfd2c82421324fdc94d544472f78528bdd862148509cab29ecdcbf9d8c4c" nocase ascii wide
                        $string33_donpapi_offensive_tool_keyword = "f93277bd46aec52cc14875cb9439a8ab5f226cf4f857196e2b423391dd67ec93" nocase ascii wide
                        $string34_donpapi_offensive_tool_keyword = "Get_DPAPI_Protected_Files" nocase ascii wide
                        $string35_donpapi_offensive_tool_keyword = "GetChromeSecrets" nocase ascii wide
                        $string36_donpapi_offensive_tool_keyword = /hashdump\.py/ nocase ascii wide
                        $string37_donpapi_offensive_tool_keyword = /lsasecrets\.py/ nocase ascii wide
                        $string38_donpapi_offensive_tool_keyword = /manager\/keepass\.py/ nocase ascii wide
                        $string39_donpapi_offensive_tool_keyword = /manager\/mRemoteNG\.py/ nocase ascii wide
                        $string40_donpapi_offensive_tool_keyword = /memorydump\.py/ nocase ascii wide
                        $string41_donpapi_offensive_tool_keyword = /mRemoteNG\-local\.py/ nocase ascii wide
                        $string42_donpapi_offensive_tool_keyword = /myseatbelt\.py/ nocase ascii wide
                        $string43_donpapi_offensive_tool_keyword = /ppypykatz\.py/ nocase ascii wide
                        $string44_donpapi_offensive_tool_keyword = /SAM\shashes\sextraction\sfor\suser\s.{0,1000}\sfailed/ nocase ascii wide

    condition:
        any of them
}