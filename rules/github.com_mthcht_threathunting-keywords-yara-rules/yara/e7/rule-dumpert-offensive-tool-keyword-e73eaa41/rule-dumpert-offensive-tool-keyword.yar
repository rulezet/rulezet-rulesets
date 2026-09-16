rule rule_Dumpert_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Dumpert' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dumpert"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Dumpert_offensive_tool_keyword = /\[\+\]\sDump\s\%wZ\smemory\sto\:\s\%wZ/ nocase ascii wide
                        $string2_Dumpert_offensive_tool_keyword = /\\Temp\\dumpert/ nocase ascii wide
                        $string3_Dumpert_offensive_tool_keyword = "1ce610dbd4ac4eaf18555046ad6001ecac4245c8d69eb4f3cc9affa10d37bacb" nocase ascii wide
                        $string4_Dumpert_offensive_tool_keyword = "307088B9-2992-4DE7-A57D-9E657B1CE546" nocase ascii wide
                        $string5_Dumpert_offensive_tool_keyword = "31f63c6923ddd1a842839f7ef1d54fec535f94760d89f0a90ad83a19dc906a8c" nocase ascii wide
                        $string6_Dumpert_offensive_tool_keyword = "48fcb3ac5d2ca4147cb46d18b662bc25262988a105fd8c93212297a07af3d615" nocase ascii wide
                        $string7_Dumpert_offensive_tool_keyword = "4bbc3665b5dd41184146e64b1b3d563af181600c9375d3e9d99170684a82a8ce" nocase ascii wide
                        $string8_Dumpert_offensive_tool_keyword = "554F8E48FA40E48E261B91A4F9F1930E099EBF337DFAC826BC41F4E850C4889F" nocase ascii wide
                        $string9_Dumpert_offensive_tool_keyword = "7202dbae30292ab2e370ff0fbcb4cdb5ef765e1e290968f7222d65c24e4645ba" nocase ascii wide
                        $string10_Dumpert_offensive_tool_keyword = "7498456870aa9d28a3ec5fd9bab4838bd4a0a35c2f41ac8da9116326337f8b7e" nocase ascii wide
                        $string11_Dumpert_offensive_tool_keyword = "80086e7ab0990319d4f61b69990eda05ff16dcd836c3b489b2bf8a189bc0c08e" nocase ascii wide
                        $string12_Dumpert_offensive_tool_keyword = "8943acdb8de2a40ca4fd8e1a2f98029aa6e8d78c9f19430b6ac557b6fb8ce4cb" nocase ascii wide
                        $string13_Dumpert_offensive_tool_keyword = "8943acdb8de2a40ca4fd8e1a2f98029aa6e8d78c9f19430b6ac557b6fb8ce4cb" nocase ascii wide
                        $string14_Dumpert_offensive_tool_keyword = "93ade5b0b20ac4c950f3610f96c9f76a8cab972e793ed6364a2f2276965690f8" nocase ascii wide
                        $string15_Dumpert_offensive_tool_keyword = "9a4b0023e443b33d85280eedb510864c42b4146c8e6e5f742444b3eff0aae55f" nocase ascii wide
                        $string16_Dumpert_offensive_tool_keyword = "9b4c57e7b68da80e3949caccaca1742dfdbe31be6f033096f8c9d72a7a0e7947" nocase ascii wide
                        $string17_Dumpert_offensive_tool_keyword = "By Cneeliz @Outflank 2019" nocase ascii wide
                        $string18_Dumpert_offensive_tool_keyword = "c23c160ea84911fa0041045b64551322f282d2d68b5c2689c4bd992c2f7c9267" nocase ascii wide
                        $string19_Dumpert_offensive_tool_keyword = "C7A0003B-98DC-4D57-8F09-5B90AAEFBDF4" nocase ascii wide
                        $string20_Dumpert_offensive_tool_keyword = "Dumpert by Outflank" nocase ascii wide
                        $string21_Dumpert_offensive_tool_keyword = /dumpert\.dmp/ nocase ascii wide
                        $string22_Dumpert_offensive_tool_keyword = /Dumpert\.exe/ nocase ascii wide
                        $string23_Dumpert_offensive_tool_keyword = /Dumpert\.git/ nocase ascii wide
                        $string24_Dumpert_offensive_tool_keyword = "Dumpert-Aggressor" nocase ascii wide
                        $string25_Dumpert_offensive_tool_keyword = "Dumpert-DLL" nocase ascii wide
                        $string26_Dumpert_offensive_tool_keyword = /dumpmethod\.dumpert/ nocase ascii wide
                        $string27_Dumpert_offensive_tool_keyword = "e05b1fa26c9571a7c6111e64a5d710f7bd03fa9795ac68a5f405ba3ac99503e5" nocase ascii wide
                        $string28_Dumpert_offensive_tool_keyword = "fe1e030312bcb26de66eea442200e4d73ff88307784fe6f1f72f776efcd5e9be" nocase ascii wide
                        $string29_Dumpert_offensive_tool_keyword = "fe1e030312bcb26de66eea442200e4d73ff88307784fe6f1f72f776efcd5e9be" nocase ascii wide
                        $string30_Dumpert_offensive_tool_keyword = "Lsass minidump can be imported in " nocase ascii wide
                        $string31_Dumpert_offensive_tool_keyword = "Outflank-Dumpert" nocase ascii wide
                        $string32_Dumpert_offensive_tool_keyword = "outflanknl/Dumpert" nocase ascii wide

    condition:
        any of them
}