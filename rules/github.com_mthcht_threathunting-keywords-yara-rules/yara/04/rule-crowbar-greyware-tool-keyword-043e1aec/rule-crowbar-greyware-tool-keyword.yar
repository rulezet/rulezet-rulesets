rule rule_crowbar_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'crowbar' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crowbar"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_crowbar_greyware_tool_keyword = /\/crowbar\.git/ nocase ascii wide
                        $string2_crowbar_greyware_tool_keyword = /\/crowbar_1\.0\.0_darwin_386\.zip/
                        $string3_crowbar_greyware_tool_keyword = /\/crowbar_1\.0\.0_darwin_amd64\.zip/
                        $string4_crowbar_greyware_tool_keyword = /\/crowbar_1\.0\.0_freebsd_386\.zip/ nocase ascii wide
                        $string5_crowbar_greyware_tool_keyword = /\/crowbar_1\.0\.0_freebsd_amd64\.zip/ nocase ascii wide
                        $string6_crowbar_greyware_tool_keyword = /\/crowbar_1\.0\.0_freebsd_arm\.zip/ nocase ascii wide
                        $string7_crowbar_greyware_tool_keyword = /\/crowbar_1\.0\.0_linux_386\.tar\.gz/
                        $string8_crowbar_greyware_tool_keyword = /\/crowbar_1\.0\.0_linux_amd64\.tar\.gz/
                        $string9_crowbar_greyware_tool_keyword = /\/crowbar_1\.0\.0_linux_arm\.tar\.gz/
                        $string10_crowbar_greyware_tool_keyword = /\/crowbar_1\.0\.0_openbsd_386\.zip/ nocase ascii wide
                        $string11_crowbar_greyware_tool_keyword = /\/crowbar_1\.0\.0_openbsd_amd64\.zip/ nocase ascii wide
                        $string12_crowbar_greyware_tool_keyword = /\/crowbar_1\.0\.0_windows_386\.zip/ nocase ascii wide
                        $string13_crowbar_greyware_tool_keyword = /\/crowbar_1\.0\.0_windows_amd64\.zip/ nocase ascii wide
                        $string14_crowbar_greyware_tool_keyword = "/etc/crowbar/"
                        $string15_crowbar_greyware_tool_keyword = /\/etc\/crowbard\.conf/
                        $string16_crowbar_greyware_tool_keyword = "47e4818c3db3471c950cdb4c4732232bafc584997098c92ada8a0f720e2ad448" nocase ascii wide
                        $string17_crowbar_greyware_tool_keyword = "4ba042e8f3a3f5cf7e01e64461d27f5733c505b8a0f221fb91ed44e93627cd91" nocase ascii wide
                        $string18_crowbar_greyware_tool_keyword = "4df132ced0bbdbe4965bea528bb11385426a938fcdec3a2905b92d800c9c8fba" nocase ascii wide
                        $string19_crowbar_greyware_tool_keyword = "515983df3a9aad4aae1e5e37cdf489686b4d7daed5610a75d75ebba006c4ddc9" nocase ascii wide
                        $string20_crowbar_greyware_tool_keyword = "602b348fd6e3407423330d761b04dfdcd8094e552c1184db100c07058343f8d4" nocase ascii wide
                        $string21_crowbar_greyware_tool_keyword = "6510e91b5511a68222bade46531b5d70850559b7da4dadd2fb187015cc811efa" nocase ascii wide
                        $string22_crowbar_greyware_tool_keyword = "8c39d2ef5bd7cb5c7aae4c5094f50cbd39b2a6c3fe65a049c91f7943f679d6b9" nocase ascii wide
                        $string23_crowbar_greyware_tool_keyword = "91bc0b2cabb6618b228003f1f7f4467b1867eae3c3f42081ee8c4e30e937e77e" nocase ascii wide
                        $string24_crowbar_greyware_tool_keyword = "9bfd1f0cb077ba95935c260cf66554142867486a42c8d84920e09dd3c6117ed1" nocase ascii wide
                        $string25_crowbar_greyware_tool_keyword = "b4bed3b73a07c019ea853ee051e35932c97a1547809697dfa495a00710dec8eb" nocase ascii wide
                        $string26_crowbar_greyware_tool_keyword = "chown crowbar:crowbar "
                        $string27_crowbar_greyware_tool_keyword = "cmd/crowbard/" nocase ascii wide
                        $string28_crowbar_greyware_tool_keyword = "crowbar-forward -local=" nocase ascii wide
                        $string29_crowbar_greyware_tool_keyword = "e4d2ed3af31f30f40f83a73dd6c4dcce275ae8cc85d52c7f30a51bfdb7ebeec2" nocase ascii wide
                        $string30_crowbar_greyware_tool_keyword = "eb459c0af8c8d7bb91f7c6acc4682f1b2a6add840925bc8a9321c5cc1e2a8137" nocase ascii wide
                        $string31_crowbar_greyware_tool_keyword = "f154878288857410353e4cabc498941869ffbbd1783f6a1923c6ed92c03dfab6" nocase ascii wide
                        $string32_crowbar_greyware_tool_keyword = "fc81435479e432562efbbb8ed75a397b565d70593af843bb1ac89628132c7ef7" nocase ascii wide
                        $string33_crowbar_greyware_tool_keyword = "q3k/crowbar" nocase ascii wide
                        $string34_crowbar_greyware_tool_keyword = "useradd -rm crowbar" nocase ascii wide

    condition:
        any of them
}