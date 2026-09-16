rule Tsunami
{
    meta:
        description = "Detection patterns for the tool 'Tsunami' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tsunami"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\stsunami\.py/ nocase ascii wide
                        $string2 = /\stsunami_warning\.py/ nocase ascii wide
                        $string3 = /\\"3R\<P4.{0,1000}\]7ye\+jT\=\,Y\%N3v\,hrWJ\^\%qH\?a\>5L\|q\[m\\"/ nocase ascii wide
                        $string4 = /\/ExecuteCommand_x64_Release\.exe/ nocase ascii wide
                        $string5 = /\/FileBasic_x64_Release\.exe/ nocase ascii wide
                        $string6 = /\/InternetConnect_x64_Release\.exe/ nocase ascii wide
                        $string7 = /\/LoaderMemoryModule_x64_Release\.exe/ nocase ascii wide
                        $string8 = /\/LoadLibrary_x64_Release\.exe/ nocase ascii wide
                        $string9 = /\/SurveyFile_x64_Release\.exe/ nocase ascii wide
                        $string10 = /\/SurveyRegistry_x64_Release\.exe/ nocase ascii wide
                        $string11 = /\/TrustedWave_x64\.exe/ nocase ascii wide
                        $string12 = /\/tsunami\.py/ nocase ascii wide
                        $string13 = /\/tsunami_warning\.py/ nocase ascii wide
                        $string14 = "/TsunamiServer/" nocase ascii wide
                        $string15 = /\/TsunamiWave_x64\.exe/ nocase ascii wide
                        $string16 = /\\ExecuteCommand_x64_Release\.exe/ nocase ascii wide
                        $string17 = /\\FileBasic_x64_Release\.exe/ nocase ascii wide
                        $string18 = /\\InternetConnect_x64_Release\.exe/ nocase ascii wide
                        $string19 = /\\LoaderMemoryModule_x64_Release\.exe/ nocase ascii wide
                        $string20 = /\\LoadLibrary_x64_Release\.exe/ nocase ascii wide
                        $string21 = /\\SurveyFile_x64_Release\.exe/ nocase ascii wide
                        $string22 = /\\SurveyRegistry_x64_Release\.exe/ nocase ascii wide
                        $string23 = /\\TrustedWave_x64\.exe/ nocase ascii wide
                        $string24 = /\\tsunami\.py/ nocase ascii wide
                        $string25 = /\\tsunami_warning\.py/ nocase ascii wide
                        $string26 = /\\TsunamiServer\\agent\\/ nocase ascii wide
                        $string27 = /\\TsunamiWave_x64\.exe/ nocase ascii wide
                        $string28 = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string29 = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string30 = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string31 = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string32 = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string33 = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string34 = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string35 = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string36 = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string37 = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string38 = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string39 = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string40 = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string41 = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string42 = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string43 = "042BF22B-7728-486B-B8C9-D5B91733C46D" nocase ascii wide
                        $string44 = "191fdeb92ab3cf8ae11e804d907366ff7ee95d92f10b88f352aeeb3ea1d8ff52" nocase ascii wide
                        $string45 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string46 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string47 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string48 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string49 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string50 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string51 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string52 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string53 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string54 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string55 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string56 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string57 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string58 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string59 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string60 = "5B5EF20C-9289-4E78-A8AF-2D30E44CF4F1" nocase ascii wide
                        $string61 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string62 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string63 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string64 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string65 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string66 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string67 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string68 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string69 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string70 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string71 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string72 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string73 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string74 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string75 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string76 = "5D21B8F0-3824-4D15-9911-1E51F2416BC2" nocase ascii wide
                        $string77 = "64==eyJzbGVlcF9zZWNvbmRzIjogMjAsICJ2YXJpYXRpb25fc2Vjb25kcyI6IDB9" nocase ascii wide
                        $string78 = "64==eyJzbGVlcF9zZWNvbmRzIjogNSwgInZhcmlhdGlvbl9zZWNvbmRzIjogNn0=" nocase ascii wide
                        $string79 = "90DEB964-F2FB-4DB8-9BCA-7D5D10D3A0EB" nocase ascii wide
                        $string80 = "97646f306c4b95f9733ee383923b7b8c954cd74715ff548ea42c8ae18fb2f67d" nocase ascii wide
                        $string81 = "E3AEA3F6-D548-4989-9A42-80BAC9321AE0" nocase ascii wide
                        $string82 = "ecec28a01376200b8746d6e2a9873d19b5191cdeb07ae926974b94d775b0c4cf" nocase ascii wide
                        $string83 = /http\:\/\/192\.168\.126\.130\/upload\.php/ nocase ascii wide
                        $string84 = /Mozilla\/5\.0\s\(compatible\,\sMSIE\s11\,\sWindows\sNT\s6\.3\;\sTrident\/7\.0\;\srv\:11\.0\)\slike\sTsunamiWave/ nocase ascii wide
                        $string85 = /use\scommand\/file_basic_upload\.json/ nocase ascii wide
                        $string86 = /use\sinteractive\/command_prompt\.json/ nocase ascii wide

    condition:
        any of them
}