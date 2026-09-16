rule rule_mRemoteNG_Decrypt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mRemoteNG-Decrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mRemoteNG-Decrypt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_mRemoteNG_Decrypt_offensive_tool_keyword = /\/decipher_mremoteng\.iml/ nocase ascii wide
                        $string2_mRemoteNG_Decrypt_offensive_tool_keyword = "/mRemoteNG-Decrypt" nocase ascii wide
                        $string3_mRemoteNG_Decrypt_offensive_tool_keyword = /\/mremoteng\-decrypt\.git/ nocase ascii wide
                        $string4_mRemoteNG_Decrypt_offensive_tool_keyword = "/mremoteng-decrypt/releases/download/" nocase ascii wide
                        $string5_mRemoteNG_Decrypt_offensive_tool_keyword = "/mremoteng-decrypt/tarball/" nocase ascii wide
                        $string6_mRemoteNG_Decrypt_offensive_tool_keyword = "/mremoteng-decrypt/zipball/" nocase ascii wide
                        $string7_mRemoteNG_Decrypt_offensive_tool_keyword = /\\mremoteng\-decrypt\\/ nocase ascii wide
                        $string8_mRemoteNG_Decrypt_offensive_tool_keyword = "3e43822dce57d12ca13a1888e2b5d653dfbf9815dd5cda87e1fc1ce29a423170" nocase ascii wide
                        $string9_mRemoteNG_Decrypt_offensive_tool_keyword = "405cd1547ee19c39e0afa83ba8ac7a53a4f88c95447df355540d82a5aa74e484" nocase ascii wide
                        $string10_mRemoteNG_Decrypt_offensive_tool_keyword = "736c69887df76672923ad7ae8b1b1754f13f96d3ae5e2eea7259e29163af71d0" nocase ascii wide
                        $string11_mRemoteNG_Decrypt_offensive_tool_keyword = "938e42fe50266db91748e07d22a54e73c9d5d25d81b5d50e475f3fc6e09d1cb1" nocase ascii wide
                        $string12_mRemoteNG_Decrypt_offensive_tool_keyword = "bbf4a68d05e79d8d2ce0bbd948a713ddafcb74b4ababa5f43c154592bc09e897" nocase ascii wide
                        $string13_mRemoteNG_Decrypt_offensive_tool_keyword = "bc600d653659564adc9f526dbba502d0b2fa47c82192b0c14fd25f45d81eec6d" nocase ascii wide
                        $string14_mRemoteNG_Decrypt_offensive_tool_keyword = "bee821a0267335398f5db2ced5c2e2687ced844c8a1627d111d4fd0692b791e6" nocase ascii wide
                        $string15_mRemoteNG_Decrypt_offensive_tool_keyword = /decipher_mremoteng\.jar/ nocase ascii wide
                        $string16_mRemoteNG_Decrypt_offensive_tool_keyword = "ebffe9aadf0e6b25df7573ca04de5b12d79ad0103d1fd936e333660b4359006c" nocase ascii wide
                        $string17_mRemoteNG_Decrypt_offensive_tool_keyword = "edf8c7fe2bd7241aafa9109be239698bc7e840097ffaec13a6a593876bdb6e97" nocase ascii wide
                        $string18_mRemoteNG_Decrypt_offensive_tool_keyword = "kmahyyg/mremoteng-decrypt" nocase ascii wide
                        $string19_mRemoteNG_Decrypt_offensive_tool_keyword = /mremoteng_decrypt\.py/ nocase ascii wide
                        $string20_mRemoteNG_Decrypt_offensive_tool_keyword = /mremoteng_decrypt\.py/ nocase ascii wide

    condition:
        any of them
}