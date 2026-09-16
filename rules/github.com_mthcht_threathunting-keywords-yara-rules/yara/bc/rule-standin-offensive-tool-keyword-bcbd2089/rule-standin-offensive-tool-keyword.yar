rule rule_StandIn_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'StandIn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "StandIn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_StandIn_offensive_tool_keyword = /\s\-\-adcs\s\-\-filter\s.{0,1000}\s\-\-ntaccount\s.{0,1000}\s\-\-enroll\s/ nocase ascii wide
                        $string2_StandIn_offensive_tool_keyword = /\s\-\-asrep\s\-\-domain\s.{0,1000}\s\-\-user\s.{0,1000}\s\-\-pass\s/ nocase ascii wide
                        $string3_StandIn_offensive_tool_keyword = /\s\-\-ldap\sservicePrincipalName\=.{0,1000}\s\-\-domain\s.{0,1000}\s\-\-user\s.{0,1000}\s\-\-pass\s/ nocase ascii wide
                        $string4_StandIn_offensive_tool_keyword = /\s\-\-passnotreq\s\-\-domain\s.{0,1000}\s\-\-user\s.{0,1000}\s\-\-pass\s/ nocase ascii wide
                        $string5_StandIn_offensive_tool_keyword = /\.exe\s\-\-asrep/ nocase ascii wide
                        $string6_StandIn_offensive_tool_keyword = /\.exe\s\-\-gpo\s\-\-filter\sadmin\s\-\-domain/ nocase ascii wide
                        $string7_StandIn_offensive_tool_keyword = /\.exe\s\-\-spn\s\-\-domain\s.{0,1000}\s\-\-user\s.{0,1000}\s\-\-pass\s/ nocase ascii wide
                        $string8_StandIn_offensive_tool_keyword = /\/StandIn\.exe/ nocase ascii wide
                        $string9_StandIn_offensive_tool_keyword = /\/StandIn\.git/ nocase ascii wide
                        $string10_StandIn_offensive_tool_keyword = /\/StandIn_Net35\.exe/ nocase ascii wide
                        $string11_StandIn_offensive_tool_keyword = /\/StandIn_Net45\.exe\s/ nocase ascii wide
                        $string12_StandIn_offensive_tool_keyword = /\/StandIn\-1\.3\.zip/ nocase ascii wide
                        $string13_StandIn_offensive_tool_keyword = /\@\\"\s\(\s_\/_\s\s\s_\/\/\s\s\s\~b33f\\"/ nocase ascii wide
                        $string14_StandIn_offensive_tool_keyword = /\[\!\]\sFailed\sto\senumerate\sADCS\sdata\./ nocase ascii wide
                        $string15_StandIn_offensive_tool_keyword = /\[\+\]\sSID\sadded\sto\smsDS\-AllowedToActOnBehalfOfOtherIdentity/ nocase ascii wide
                        $string16_StandIn_offensive_tool_keyword = /\\CultesDesGoules\.txt/ nocase ascii wide
                        $string17_StandIn_offensive_tool_keyword = /\\nMethodNamespace\=StandIn/ nocase ascii wide
                        $string18_StandIn_offensive_tool_keyword = /\\StandIn\s\-\-/ nocase ascii wide
                        $string19_StandIn_offensive_tool_keyword = /\\StandIn\.exe/ nocase ascii wide
                        $string20_StandIn_offensive_tool_keyword = /\\StandIn\.pdb/ nocase ascii wide
                        $string21_StandIn_offensive_tool_keyword = /\\StandIn\\hStandIn\.cs/ nocase ascii wide
                        $string22_StandIn_offensive_tool_keyword = /\\StandIn\\Program\.cs/ nocase ascii wide
                        $string23_StandIn_offensive_tool_keyword = /\\StandIn_Net35\.exe/ nocase ascii wide
                        $string24_StandIn_offensive_tool_keyword = /\\StandIn_Net45\.exe\s/ nocase ascii wide
                        $string25_StandIn_offensive_tool_keyword = /\\StandIn\-1\.3\.zip/ nocase ascii wide
                        $string26_StandIn_offensive_tool_keyword = "01C142BA-7AF1-48D6-B185-81147A2F7DB7" nocase ascii wide
                        $string27_StandIn_offensive_tool_keyword = "24C53132B594B77D2109CAEE3E276EA4603EEF32BFECD5121746DB58258C50F7" nocase ascii wide
                        $string28_StandIn_offensive_tool_keyword = "2E37A3D2DC2ECB0BD026C93055A71CAB4E568B062B1C9F7B8846E04DF1E9F3E6" nocase ascii wide
                        $string29_StandIn_offensive_tool_keyword = "94dc145b517036213443d4057d400296d40ffdcd50ba63f5304796060790c8a3" nocase ascii wide
                        $string30_StandIn_offensive_tool_keyword = "A0B3C96CA89770ED04E37D43188427E0016B42B03C0102216C5F6A785B942BD3" nocase ascii wide
                        $string31_StandIn_offensive_tool_keyword = "A1ECD50DA8AAE5734A5F5C4A6A951B5F3C99CC4FB939AC60EF5EE19896CA23A0" nocase ascii wide
                        $string32_StandIn_offensive_tool_keyword = "C2ACD3667483E5AC1E423E482DBA462E96DA3978776BFED07D9B436FEE135AB2" nocase ascii wide
                        $string33_StandIn_offensive_tool_keyword = "DBAB7B9CC694FC37354E3A18F9418586172ED6660D8D205EAFFF945525A6A31A" nocase ascii wide
                        $string34_StandIn_offensive_tool_keyword = "DCCDA4991BEBC5F2399C47C798981E7828ECC2BA77ED52A1D37BD866AD5582AA" nocase ascii wide
                        $string35_StandIn_offensive_tool_keyword = "F80AEB33FC53F2C8D6313A6B20CD117739A71382C208702B43073D54C9ACA681" nocase ascii wide
                        $string36_StandIn_offensive_tool_keyword = /FullyQualifiedAssemblyName\=0\;\\\\r\\\\nClrInstanceID\=StandIn/ nocase ascii wide
                        $string37_StandIn_offensive_tool_keyword = "FuzzySecurity/StandIn" nocase ascii wide
                        $string38_StandIn_offensive_tool_keyword = "MlCGkaacS5SRUOt" nocase ascii wide
                        $string39_StandIn_offensive_tool_keyword = /StandIn\.exe\s\-\-/ nocase ascii wide
                        $string40_StandIn_offensive_tool_keyword = /StandIn\.exe\\"\s\-\-/ nocase ascii wide
                        $string41_StandIn_offensive_tool_keyword = /StandIn_v12_Net35_45\.zip/ nocase ascii wide
                        $string42_StandIn_offensive_tool_keyword = /StandIn_v13_Net35_45\.zip/ nocase ascii wide

    condition:
        any of them
}