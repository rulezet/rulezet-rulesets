rule rule_RealBlindingEDR_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RealBlindingEDR' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RealBlindingEDR"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RealBlindingEDR_offensive_tool_keyword = /\.exe\sc\:\\.{0,100}\.sys\s3\sclear/ nocase ascii wide
                        $string2_RealBlindingEDR_offensive_tool_keyword = /\/RealBlindingEDR\.git/ nocase ascii wide
                        $string3_RealBlindingEDR_offensive_tool_keyword = "/RealBlindingEDR/tarball" nocase ascii wide
                        $string4_RealBlindingEDR_offensive_tool_keyword = "/RealBlindingEDR/zipball" nocase ascii wide
                        $string5_RealBlindingEDR_offensive_tool_keyword = /\\RealBlindingEDR\.vcxproj/ nocase ascii wide
                        $string6_RealBlindingEDR_offensive_tool_keyword = /\\RealBlindingEDR\\/ nocase ascii wide
                        $string7_RealBlindingEDR_offensive_tool_keyword = "082f932faefd33a4e3500c5cb8e119e09d5f914de6d18f16162b48bba15bb7d4" nocase ascii wide
                        $string8_RealBlindingEDR_offensive_tool_keyword = "09efed04888379b1fa6378ec5c4a944626129d92793a132ff56ab5d11fe53714" nocase ascii wide
                        $string9_RealBlindingEDR_offensive_tool_keyword = "11360c9e4f50a098a4abfc0d6c6d19b8fa73ca872c462dc4e9b3d6a24a5abb22" nocase ascii wide
                        $string10_RealBlindingEDR_offensive_tool_keyword = "209948811ece8dd5cff6fab03402232677c2625fad1272ddc964ed7869b46eeb" nocase ascii wide
                        $string11_RealBlindingEDR_offensive_tool_keyword = "283b1a457e8aff360521928e64447e360752cc978287e51f67934fc803699c11" nocase ascii wide
                        $string12_RealBlindingEDR_offensive_tool_keyword = "2c2e4a89c50f2f7fdb136b2435074b271f0574b0fa4629aacb6cffbc05d5940b" nocase ascii wide
                        $string13_RealBlindingEDR_offensive_tool_keyword = "349728a1f521a0584cd5da88fd781c2927a6b2b6da356d79279b695c0af987b6" nocase ascii wide
                        $string14_RealBlindingEDR_offensive_tool_keyword = "6a48338880ea3ada4e5675edda95cfa57976ee18b6de9fbf6ab5ce545ee42ea8" nocase ascii wide
                        $string15_RealBlindingEDR_offensive_tool_keyword = "6f430900ee17bc63c79e6c42bfff16829205948b1e136bd4bc6d02301ba09d76" nocase ascii wide
                        $string16_RealBlindingEDR_offensive_tool_keyword = "75f525cfddff5015fe3aada97fd9ed1b51657297f1f5fa494c3b73ad7766105a" nocase ascii wide
                        $string17_RealBlindingEDR_offensive_tool_keyword = "7eafe227a92bd29f811ecf7457d7170ffe65962b5048a8b431c68bc1121fac21" nocase ascii wide
                        $string18_RealBlindingEDR_offensive_tool_keyword = "7f8e123e9191b4e2299eb159da8776f51430445847529ff1f01b469acb04be2b" nocase ascii wide
                        $string19_RealBlindingEDR_offensive_tool_keyword = "81fc4f198955aef68c590f3c04dc1fd4184a7e7b55648a67422a51f3dcf79382" nocase ascii wide
                        $string20_RealBlindingEDR_offensive_tool_keyword = "A62776D0-CF96-4067-B4BE-B337AB6DFF02" nocase ascii wide
                        $string21_RealBlindingEDR_offensive_tool_keyword = "aa8b4f53e6ca8db9d8b13db3b0a250724b9ef472d99bb5c1ad0da8e10f7c95c7" nocase ascii wide
                        $string22_RealBlindingEDR_offensive_tool_keyword = "aac934f5656f3d2f861a4e0ccaa83175bb2fa9f5b8d893192ec287f2097bf18a" nocase ascii wide
                        $string23_RealBlindingEDR_offensive_tool_keyword = "ac62eec9b4b7616cd207fda9ff22de6905f3872dcc81d03e5d67fe87e4e3b448" nocase ascii wide
                        $string24_RealBlindingEDR_offensive_tool_keyword = "acac4db9c3f6c44711409a3fb564de89a747643d53b8d65c9c3a06e56f28875f" nocase ascii wide
                        $string25_RealBlindingEDR_offensive_tool_keyword = "b697318c942f44d36de647d4054759b7297ff90aba4de22d41488698b9d3e32c" nocase ascii wide
                        $string26_RealBlindingEDR_offensive_tool_keyword = "bXl6LnhjZ0BnbWFpbC5jb20=" nocase ascii wide
                        $string27_RealBlindingEDR_offensive_tool_keyword = /c\:\\\\echo_driver\.sys/ nocase ascii wide
                        $string28_RealBlindingEDR_offensive_tool_keyword = /CreateFile\(L\\"\\\\\\\\\.\\\\EchoDrv/ nocase ascii wide
                        $string29_RealBlindingEDR_offensive_tool_keyword = "dad3df98ecb98bce9aee81b110ce6fca2ebba82fd56df1507b0a97688eb8d9bc" nocase ascii wide
                        $string30_RealBlindingEDR_offensive_tool_keyword = "f4029b49066c2eaacff2b8ff2cc6b0c2869720666d21432eb080c489a261678c" nocase ascii wide
                        $string31_RealBlindingEDR_offensive_tool_keyword = /myz\.xcg\@gmail\.com/ nocase ascii wide
                        $string32_RealBlindingEDR_offensive_tool_keyword = "myzxcg/RealBlindingEDR" nocase ascii wide
                        $string33_RealBlindingEDR_offensive_tool_keyword = /RealBlindingEDR\.cpp/ nocase ascii wide
                        $string34_RealBlindingEDR_offensive_tool_keyword = /RealBlindingEDR\.exe/ nocase ascii wide
                        $string35_RealBlindingEDR_offensive_tool_keyword = /RealBlindingEDR\.h/ nocase ascii wide
                        $string36_RealBlindingEDR_offensive_tool_keyword = "RealBlindingEDR/releases" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}