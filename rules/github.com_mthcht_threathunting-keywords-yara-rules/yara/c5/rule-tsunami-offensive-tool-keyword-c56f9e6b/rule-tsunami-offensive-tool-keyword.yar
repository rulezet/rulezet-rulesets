rule rule_Tsunami_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Tsunami' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tsunami"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Tsunami_offensive_tool_keyword = /\stsunami\.py/ nocase ascii wide
                        $string2_Tsunami_offensive_tool_keyword = /\stsunami_warning\.py/ nocase ascii wide
                        $string3_Tsunami_offensive_tool_keyword = /\\"3R\<P4.{0,1000}\]7ye\+jT\=\,Y\%N3v\,hrWJ\^\%qH\?a\>5L\|q\[m\\"/ nocase ascii wide
                        $string4_Tsunami_offensive_tool_keyword = /\/ExecuteCommand_x64_Release\.exe/ nocase ascii wide
                        $string5_Tsunami_offensive_tool_keyword = /\/FileBasic_x64_Release\.exe/ nocase ascii wide
                        $string6_Tsunami_offensive_tool_keyword = /\/InternetConnect_x64_Release\.exe/ nocase ascii wide
                        $string7_Tsunami_offensive_tool_keyword = /\/LoaderMemoryModule_x64_Release\.exe/ nocase ascii wide
                        $string8_Tsunami_offensive_tool_keyword = /\/LoadLibrary_x64_Release\.exe/ nocase ascii wide
                        $string9_Tsunami_offensive_tool_keyword = /\/SurveyFile_x64_Release\.exe/ nocase ascii wide
                        $string10_Tsunami_offensive_tool_keyword = /\/SurveyRegistry_x64_Release\.exe/ nocase ascii wide
                        $string11_Tsunami_offensive_tool_keyword = /\/TrustedWave_x64\.exe/ nocase ascii wide
                        $string12_Tsunami_offensive_tool_keyword = /\/tsunami\.py/ nocase ascii wide
                        $string13_Tsunami_offensive_tool_keyword = /\/tsunami_warning\.py/ nocase ascii wide
                        $string14_Tsunami_offensive_tool_keyword = "/TsunamiServer/" nocase ascii wide
                        $string15_Tsunami_offensive_tool_keyword = /\/TsunamiWave_x64\.exe/ nocase ascii wide
                        $string16_Tsunami_offensive_tool_keyword = /\\ExecuteCommand_x64_Release\.exe/ nocase ascii wide
                        $string17_Tsunami_offensive_tool_keyword = /\\FileBasic_x64_Release\.exe/ nocase ascii wide
                        $string18_Tsunami_offensive_tool_keyword = /\\InternetConnect_x64_Release\.exe/ nocase ascii wide
                        $string19_Tsunami_offensive_tool_keyword = /\\LoaderMemoryModule_x64_Release\.exe/ nocase ascii wide
                        $string20_Tsunami_offensive_tool_keyword = /\\LoadLibrary_x64_Release\.exe/ nocase ascii wide
                        $string21_Tsunami_offensive_tool_keyword = /\\SurveyFile_x64_Release\.exe/ nocase ascii wide
                        $string22_Tsunami_offensive_tool_keyword = /\\SurveyRegistry_x64_Release\.exe/ nocase ascii wide
                        $string23_Tsunami_offensive_tool_keyword = /\\TrustedWave_x64\.exe/ nocase ascii wide
                        $string24_Tsunami_offensive_tool_keyword = /\\tsunami\.py/ nocase ascii wide
                        $string25_Tsunami_offensive_tool_keyword = /\\tsunami_warning\.py/ nocase ascii wide
                        $string26_Tsunami_offensive_tool_keyword = /\\TsunamiServer\\agent\\/ nocase ascii wide
                        $string27_Tsunami_offensive_tool_keyword = /\\TsunamiWave_x64\.exe/ nocase ascii wide
                        $string28_Tsunami_offensive_tool_keyword = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string29_Tsunami_offensive_tool_keyword = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string30_Tsunami_offensive_tool_keyword = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string31_Tsunami_offensive_tool_keyword = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string32_Tsunami_offensive_tool_keyword = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string33_Tsunami_offensive_tool_keyword = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string34_Tsunami_offensive_tool_keyword = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string35_Tsunami_offensive_tool_keyword = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string36_Tsunami_offensive_tool_keyword = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string37_Tsunami_offensive_tool_keyword = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string38_Tsunami_offensive_tool_keyword = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string39_Tsunami_offensive_tool_keyword = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string40_Tsunami_offensive_tool_keyword = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string41_Tsunami_offensive_tool_keyword = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string42_Tsunami_offensive_tool_keyword = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string43_Tsunami_offensive_tool_keyword = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string44_Tsunami_offensive_tool_keyword = "191fdeb92ab3cf8ae11e804d907366ff7ee95d92f10b88f352aeeb3ea1d8ff52" nocase ascii wide
                        $string45_Tsunami_offensive_tool_keyword = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string46_Tsunami_offensive_tool_keyword = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string47_Tsunami_offensive_tool_keyword = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string48_Tsunami_offensive_tool_keyword = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string49_Tsunami_offensive_tool_keyword = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string50_Tsunami_offensive_tool_keyword = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string51_Tsunami_offensive_tool_keyword = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string52_Tsunami_offensive_tool_keyword = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string53_Tsunami_offensive_tool_keyword = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string54_Tsunami_offensive_tool_keyword = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string55_Tsunami_offensive_tool_keyword = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string56_Tsunami_offensive_tool_keyword = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string57_Tsunami_offensive_tool_keyword = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string58_Tsunami_offensive_tool_keyword = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string59_Tsunami_offensive_tool_keyword = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string60_Tsunami_offensive_tool_keyword = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string61_Tsunami_offensive_tool_keyword = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string62_Tsunami_offensive_tool_keyword = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string63_Tsunami_offensive_tool_keyword = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string64_Tsunami_offensive_tool_keyword = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string65_Tsunami_offensive_tool_keyword = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string66_Tsunami_offensive_tool_keyword = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string67_Tsunami_offensive_tool_keyword = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string68_Tsunami_offensive_tool_keyword = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string69_Tsunami_offensive_tool_keyword = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string70_Tsunami_offensive_tool_keyword = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string71_Tsunami_offensive_tool_keyword = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string72_Tsunami_offensive_tool_keyword = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string73_Tsunami_offensive_tool_keyword = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string74_Tsunami_offensive_tool_keyword = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string75_Tsunami_offensive_tool_keyword = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string76_Tsunami_offensive_tool_keyword = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string77_Tsunami_offensive_tool_keyword = "64==eyJzbGVlcF9zZWNvbmRzIjogMjAsICJ2YXJpYXRpb25fc2Vjb25kcyI6IDB9" nocase ascii wide
                        $string78_Tsunami_offensive_tool_keyword = "64==eyJzbGVlcF9zZWNvbmRzIjogNSwgInZhcmlhdGlvbl9zZWNvbmRzIjogNn0=" nocase ascii wide
                        $string79_Tsunami_offensive_tool_keyword = "90DEB964-F2FB-4DB8-9BCA-7D5D10D3A0EB" nocase ascii wide
                        $string80_Tsunami_offensive_tool_keyword = "97646f306c4b95f9733ee383923b7b8c954cd74715ff548ea42c8ae18fb2f67d" nocase ascii wide
                        $string81_Tsunami_offensive_tool_keyword = "E3AEA3F6-D548-4989-9A42-80BAC9321AE0" nocase ascii wide
                        $string82_Tsunami_offensive_tool_keyword = "ecec28a01376200b8746d6e2a9873d19b5191cdeb07ae926974b94d775b0c4cf" nocase ascii wide
                        $string83_Tsunami_offensive_tool_keyword = /http\:\/\/192\.168\.126\.130\/upload\.php/ nocase ascii wide
                        $string84_Tsunami_offensive_tool_keyword = /Mozilla\/5\.0\s\(compatible\,\sMSIE\s11\,\sWindows\sNT\s6\.3\;\sTrident\/7\.0\;\srv\:11\.0\)\slike\sTsunamiWave/ nocase ascii wide
                        $string85_Tsunami_offensive_tool_keyword = /use\scommand\/file_basic_upload\.json/ nocase ascii wide
                        $string86_Tsunami_offensive_tool_keyword = /use\sinteractive\/command_prompt\.json/ nocase ascii wide

    condition:
        any of them
}