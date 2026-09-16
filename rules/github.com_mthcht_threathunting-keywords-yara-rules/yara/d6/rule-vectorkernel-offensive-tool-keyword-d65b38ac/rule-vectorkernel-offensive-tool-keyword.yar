rule rule_VectorKernel_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VectorKernel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VectorKernel"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_VectorKernel_offensive_tool_keyword = /\/VectorKernel\.git/ nocase ascii wide
                        $string2_VectorKernel_offensive_tool_keyword = /\\\\Device\\\\StealToken/ nocase ascii wide
                        $string3_VectorKernel_offensive_tool_keyword = /\\GetFullPrivs\\GetFullPrivs/ nocase ascii wide
                        $string4_VectorKernel_offensive_tool_keyword = /\\GetFullPrivsDrv\.cpp/ nocase ascii wide
                        $string5_VectorKernel_offensive_tool_keyword = /\\GetFullPrivsDrv\.exe/ nocase ascii wide
                        $string6_VectorKernel_offensive_tool_keyword = /\\GetProcHandleDrv_x64\.sys/ nocase ascii wide
                        $string7_VectorKernel_offensive_tool_keyword = /\\ProcProtectClient\.exe/ nocase ascii wide
                        $string8_VectorKernel_offensive_tool_keyword = /\\QueryModuleClient\.exe/ nocase ascii wide
                        $string9_VectorKernel_offensive_tool_keyword = /\\StealTokenClient\.exe/ nocase ascii wide
                        $string10_VectorKernel_offensive_tool_keyword = /\\StealTokenDrv\.cpp/ nocase ascii wide
                        $string11_VectorKernel_offensive_tool_keyword = /\\StealTokenDrv\.exe/ nocase ascii wide
                        $string12_VectorKernel_offensive_tool_keyword = "02EF15C0-BA19-4115-BB7F-F5B04F7087FE" nocase ascii wide
                        $string13_VectorKernel_offensive_tool_keyword = "0C89EC7D-AC60-4591-8F6B-CB5F20EC0D8D" nocase ascii wide
                        $string14_VectorKernel_offensive_tool_keyword = "1250BAE1-D26F-4EF2-9452-9B5009568336" nocase ascii wide
                        $string15_VectorKernel_offensive_tool_keyword = "171A9A71-EDEF-4891-9828-44434A00585E" nocase ascii wide
                        $string16_VectorKernel_offensive_tool_keyword = "28F9E001-67E0-4200-B120-3021596689E9" nocase ascii wide
                        $string17_VectorKernel_offensive_tool_keyword = "2FB94059-2D49-4EEA-AAF8-7E89E249644B" nocase ascii wide
                        $string18_VectorKernel_offensive_tool_keyword = "3F0C3D9A-CFB8-4DB5-8419-1C28CBC8621D" nocase ascii wide
                        $string19_VectorKernel_offensive_tool_keyword = "3FBBC3DD-39D9-4D8C-AF73-EDC3D2849DEB" nocase ascii wide
                        $string20_VectorKernel_offensive_tool_keyword = "51E46096-4A36-4C7D-9773-BC28DBDC4FC6" nocase ascii wide
                        $string21_VectorKernel_offensive_tool_keyword = "56F981FD-634A-4656-85A7-5636658E1F94" nocase ascii wide
                        $string22_VectorKernel_offensive_tool_keyword = "628E42D5-AE4F-4CDD-8D14-DAB1A3697B62" nocase ascii wide
                        $string23_VectorKernel_offensive_tool_keyword = "9E5A6F99-0A26-4959-847D-A4221CF4441B" nocase ascii wide
                        $string24_VectorKernel_offensive_tool_keyword = "9EFFFF7A-DC03-4D52-BB8F-F0140FAD26E7" nocase ascii wide
                        $string25_VectorKernel_offensive_tool_keyword = "9FEA6712-3880-4E5F-BD56-8E58A4EBCCB4" nocase ascii wide
                        $string26_VectorKernel_offensive_tool_keyword = "A017568E-B62E-46B4-9557-15B278656365" nocase ascii wide
                        $string27_VectorKernel_offensive_tool_keyword = "AD0067D9-4AF6-47C2-B0C3-D768A9624002" nocase ascii wide
                        $string28_VectorKernel_offensive_tool_keyword = "B9635D08-2BB2-404B-92B7-6A4981CB34F3" nocase ascii wide
                        $string29_VectorKernel_offensive_tool_keyword = "BDED2735-F9E4-4B2E-9636-4EEDD78FC720" nocase ascii wide
                        $string30_VectorKernel_offensive_tool_keyword = /BlockNewProcClient\.exe\s\-/ nocase ascii wide
                        $string31_VectorKernel_offensive_tool_keyword = /BlockNewProcDrv_x64\.sys/ nocase ascii wide
                        $string32_VectorKernel_offensive_tool_keyword = "C7F1F871-8045-4414-9DC3-20F8AA42B4A1" nocase ascii wide
                        $string33_VectorKernel_offensive_tool_keyword = "C8C12FA3-717F-4D35-B8B3-2E7F7A124E7C" nocase ascii wide
                        $string34_VectorKernel_offensive_tool_keyword = /CreateTokenClient\.exe\s/ nocase ascii wide
                        $string35_VectorKernel_offensive_tool_keyword = /CreateTokenDrv_x64\.sys/ nocase ascii wide
                        $string36_VectorKernel_offensive_tool_keyword = "D19BD978-267A-4BF0-85CC-851E280FF4C2" nocase ascii wide
                        $string37_VectorKernel_offensive_tool_keyword = "daem0nc0re/VectorKernel" nocase ascii wide
                        $string38_VectorKernel_offensive_tool_keyword = "FC5A1C5A-65B4-452A-AA4E-E6DCF1FA04FB" nocase ascii wide
                        $string39_VectorKernel_offensive_tool_keyword = /GetFullPrivsClient\.exe/ nocase ascii wide
                        $string40_VectorKernel_offensive_tool_keyword = /GetFullPrivsDrv_x64\.sys/ nocase ascii wide
                        $string41_VectorKernel_offensive_tool_keyword = /GetProcHandleClient\.exe\s/ nocase ascii wide
                        $string42_VectorKernel_offensive_tool_keyword = /InjectLibraryClient\.exe\s\-/ nocase ascii wide
                        $string43_VectorKernel_offensive_tool_keyword = /InjectLibraryDrv_x64\.sys/ nocase ascii wide
                        $string44_VectorKernel_offensive_tool_keyword = /ModHideDrv_x64\.sys/ nocase ascii wide
                        $string45_VectorKernel_offensive_tool_keyword = /ProcHideClient\.exe\s\-/ nocase ascii wide
                        $string46_VectorKernel_offensive_tool_keyword = /ProcHideDrv_x64\.sys/ nocase ascii wide
                        $string47_VectorKernel_offensive_tool_keyword = /ProcProtectClient\.exe\s/ nocase ascii wide
                        $string48_VectorKernel_offensive_tool_keyword = /StealTokenClient\.exe\s/ nocase ascii wide
                        $string49_VectorKernel_offensive_tool_keyword = /StealTokenClient\\StealTokenClient\.cs/ nocase ascii wide
                        $string50_VectorKernel_offensive_tool_keyword = /StealTokenDrv_x64\.sys/ nocase ascii wide
                        $string51_VectorKernel_offensive_tool_keyword = /VectorKernel\\BlockNewProc/ nocase ascii wide
                        $string52_VectorKernel_offensive_tool_keyword = /VectorKernel\\CreateToken/ nocase ascii wide
                        $string53_VectorKernel_offensive_tool_keyword = /VectorKernel\\ModHide/ nocase ascii wide
                        $string54_VectorKernel_offensive_tool_keyword = /VectorKernel\\StealToken/ nocase ascii wide
                        $string55_VectorKernel_offensive_tool_keyword = /VectorKernel\-main\.zip/ nocase ascii wide

    condition:
        any of them
}