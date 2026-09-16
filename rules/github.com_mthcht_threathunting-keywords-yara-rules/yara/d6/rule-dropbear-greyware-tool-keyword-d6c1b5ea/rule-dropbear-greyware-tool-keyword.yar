rule rule_dropbear_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dropbear' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dropbear"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_dropbear_greyware_tool_keyword = /\.\/dropbear\s/
                        $string2_dropbear_greyware_tool_keyword = /\/\.ssh\/dropbear/
                        $string3_dropbear_greyware_tool_keyword = "/bin/dropbear"
                        $string4_dropbear_greyware_tool_keyword = /\/dropbear\.git/ nocase ascii wide
                        $string5_dropbear_greyware_tool_keyword = /\/dropbear\.init/
                        $string6_dropbear_greyware_tool_keyword = /\/dropbear\.log/
                        $string7_dropbear_greyware_tool_keyword = "/dropbear/releases/" nocase ascii wide
                        $string8_dropbear_greyware_tool_keyword = "/dropbear_dss_host_key"
                        $string9_dropbear_greyware_tool_keyword = "/dropbear_rsa_host_key"
                        $string10_dropbear_greyware_tool_keyword = "/etc/default/dropbear"
                        $string11_dropbear_greyware_tool_keyword = "/etc/dropbear/"
                        $string12_dropbear_greyware_tool_keyword = "/sbin/dropbear"
                        $string13_dropbear_greyware_tool_keyword = "/tmp/dropbear"
                        $string14_dropbear_greyware_tool_keyword = "1a338c455c8cf9b8499c16e26cfa7e4b34109cf441045a6d006a8d9aa8d852bb" nocase ascii wide
                        $string15_dropbear_greyware_tool_keyword = "27d7590cf6e7386f9df2777e5f2b1e3473fe990182b2ad8bf31a33b0f5436be4" nocase ascii wide
                        $string16_dropbear_greyware_tool_keyword = "2d65a1cab58434497155118ca19bd1202900532375a4d1356a0e60463437f924" nocase ascii wide
                        $string17_dropbear_greyware_tool_keyword = "317459a7d2933c3bb095b5c4d188c83ce6dbed8dd9f282cd3406c9f364a04363" nocase ascii wide
                        $string18_dropbear_greyware_tool_keyword = "504764d19a025b282b230491d91abbc551f1b9887ee669bbb7211b6dd86b1038" nocase ascii wide
                        $string19_dropbear_greyware_tool_keyword = "5f4e2217fe4e88c926dbe4d002e5bfaa47591a6e53b93df88596a654aaeae78d" nocase ascii wide
                        $string20_dropbear_greyware_tool_keyword = "81f14b29b131156c433a46709e83bbe8deeee87c4bb9db4d45171ece944f6612" nocase ascii wide
                        $string21_dropbear_greyware_tool_keyword = "b17a74e58d85f8d1ecfa38831fbca197c8edeb92e6c3a856e8c6b1030149ebe7" nocase ascii wide
                        $string22_dropbear_greyware_tool_keyword = "b6a919990fe576710a4ce3ed46cc40d91ce4d59e547af8c50b739920987b7e44" nocase ascii wide
                        $string23_dropbear_greyware_tool_keyword = "b96e491df170080d656cf7e24dd085bc15e044e72c5bbbd6abbe3bcc230b328d" nocase ascii wide
                        $string24_dropbear_greyware_tool_keyword = "bc40d2839a4942652d9a765b64a024b600b2dd3b3205f845d77b93d458b039b9" nocase ascii wide
                        $string25_dropbear_greyware_tool_keyword = "bd4c534c458ff68d34112516e281ba763093dcb9ab531ccc3e6c95b5aef667d8" nocase ascii wide
                        $string26_dropbear_greyware_tool_keyword = "dd9f9362f115314d3ba6b5eb8e49128fd5052e195a679caae0729640ef42d95f" nocase ascii wide
                        $string27_dropbear_greyware_tool_keyword = "dropbearconvert openssh dropbear" nocase ascii wide
                        $string28_dropbear_greyware_tool_keyword = "dropbearkey -t " nocase ascii wide
                        $string29_dropbear_greyware_tool_keyword = "dropbearkey -y -f " nocase ascii wide
                        $string30_dropbear_greyware_tool_keyword = "eb912ff679743d91907286544c7326df785a3a6e6992fa182404e3fbae52958a" nocase ascii wide
                        $string31_dropbear_greyware_tool_keyword = "exec dropbear " nocase ascii wide
                        $string32_dropbear_greyware_tool_keyword = /invoke\-rc\.d\sdropbear\s/ nocase ascii wide
                        $string33_dropbear_greyware_tool_keyword = "mkj/dropbear" nocase ascii wide

    condition:
        any of them
}