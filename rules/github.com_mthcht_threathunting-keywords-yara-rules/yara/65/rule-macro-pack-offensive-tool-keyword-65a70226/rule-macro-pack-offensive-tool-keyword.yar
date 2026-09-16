rule rule_macro_pack_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'macro_pack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "macro_pack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_macro_pack_offensive_tool_keyword = " --bypass --stealth --antisandox" nocase ascii wide
                        $string2_macro_pack_offensive_tool_keyword = /\smacro_pack\.py/ nocase ascii wide
                        $string3_macro_pack_offensive_tool_keyword = /\smimidropper\.hta/ nocase ascii wide
                        $string4_macro_pack_offensive_tool_keyword = /\smsfvenom\.bat/ nocase ascii wide
                        $string5_macro_pack_offensive_tool_keyword = /\/Base64ToBin\.py/ nocase ascii wide
                        $string6_macro_pack_offensive_tool_keyword = /\/hta_gen\.py/ nocase ascii wide
                        $string7_macro_pack_offensive_tool_keyword = /\/macro_pack\.exe/ nocase ascii wide
                        $string8_macro_pack_offensive_tool_keyword = /\/macro_pack\.git/ nocase ascii wide
                        $string9_macro_pack_offensive_tool_keyword = /\/macro_pack\.py/ nocase ascii wide
                        $string10_macro_pack_offensive_tool_keyword = "/macro_pack/releases/download/" nocase ascii wide
                        $string11_macro_pack_offensive_tool_keyword = /\/Meterpreter\.py/ nocase ascii wide
                        $string12_macro_pack_offensive_tool_keyword = /\/meterpreter\.rc/ nocase ascii wide
                        $string13_macro_pack_offensive_tool_keyword = /\/mimidropper\.hta/ nocase ascii wide
                        $string14_macro_pack_offensive_tool_keyword = /\/msfvenom\.bat/ nocase ascii wide
                        $string15_macro_pack_offensive_tool_keyword = /\/obfuscate_strings\.py/ nocase ascii wide
                        $string16_macro_pack_offensive_tool_keyword = /\/payload\.hta/ nocase ascii wide
                        $string17_macro_pack_offensive_tool_keyword = /\/uac_bypass\.py/ nocase ascii wide
                        $string18_macro_pack_offensive_tool_keyword = /\/vba_gen\.py/ nocase ascii wide
                        $string19_macro_pack_offensive_tool_keyword = /\[\+\]\sStarting\sMacro_Pack\sweb\sserver/ nocase ascii wide
                        $string20_macro_pack_offensive_tool_keyword = /\\Base64ToBin\.py/ nocase ascii wide
                        $string21_macro_pack_offensive_tool_keyword = /\\empire_stager\.cmd/ nocase ascii wide
                        $string22_macro_pack_offensive_tool_keyword = /\\hta_gen\.py/ nocase ascii wide
                        $string23_macro_pack_offensive_tool_keyword = /\\macro_pack\.exe/ nocase ascii wide
                        $string24_macro_pack_offensive_tool_keyword = /\\macro_pack\.py/ nocase ascii wide
                        $string25_macro_pack_offensive_tool_keyword = /\\Meterpreter\.py/ nocase ascii wide
                        $string26_macro_pack_offensive_tool_keyword = /\\meterpreter\.rc/ nocase ascii wide
                        $string27_macro_pack_offensive_tool_keyword = /\\mimidropper\.hta/ nocase ascii wide
                        $string28_macro_pack_offensive_tool_keyword = /\\msfvenom\.bat/ nocase ascii wide
                        $string29_macro_pack_offensive_tool_keyword = /\\obfuscate_strings\.py/ nocase ascii wide
                        $string30_macro_pack_offensive_tool_keyword = /\\payload\.hta/ nocase ascii wide
                        $string31_macro_pack_offensive_tool_keyword = /\\uac_bypass\.py/ nocase ascii wide
                        $string32_macro_pack_offensive_tool_keyword = /\\vba_gen\.py/ nocase ascii wide
                        $string33_macro_pack_offensive_tool_keyword = /_processDropper2Template\(/ nocase ascii wide
                        $string34_macro_pack_offensive_tool_keyword = /_processDropperDllTemplate\(/ nocase ascii wide
                        $string35_macro_pack_offensive_tool_keyword = /_processDropperTemplate\(/ nocase ascii wide
                        $string36_macro_pack_offensive_tool_keyword = /_processEmbedDllTemplate\(/ nocase ascii wide
                        $string37_macro_pack_offensive_tool_keyword = /_processEmbedExeTemplate\(/ nocase ascii wide
                        $string38_macro_pack_offensive_tool_keyword = /_processMeterpreterTemplate\(/ nocase ascii wide
                        $string39_macro_pack_offensive_tool_keyword = /_processPowershellDropperTemplate\(/ nocase ascii wide
                        $string40_macro_pack_offensive_tool_keyword = "0365439c99fbf26126da61350ad8c424c6c0064c7cb3a9d2bc0b56674b01ed7c" nocase ascii wide
                        $string41_macro_pack_offensive_tool_keyword = "049003aa4e196b115dd292dcb19a0308b45bfc160344a2f18edb537800b9d38e" nocase ascii wide
                        $string42_macro_pack_offensive_tool_keyword = "05043d8400b0be454879f8d7f4c4455afa7ef1c9705176d1d95334f36e84bd53" nocase ascii wide
                        $string43_macro_pack_offensive_tool_keyword = "07f1a35a2a86c46c5b0f70176aaacd6268b3dbf639d77bcf1b89235e8b44f327" nocase ascii wide
                        $string44_macro_pack_offensive_tool_keyword = "205adce8325494081e929d923abc6585ae541546172483dc147b6ffe48b4f7f6" nocase ascii wide
                        $string45_macro_pack_offensive_tool_keyword = "20b19292fa127311c14f893694a72b376d27b88c56ea2fb7b9fb816d9e0ab4d6" nocase ascii wide
                        $string46_macro_pack_offensive_tool_keyword = "23bffbd2241b534574b8a9149c2502da4960f3a185437a9f983e51eebaf8ee1d" nocase ascii wide
                        $string47_macro_pack_offensive_tool_keyword = "3ecabb1f5934079ee820bfe9f238ce6d780c2228563f55002a5921b1800118e1" nocase ascii wide
                        $string48_macro_pack_offensive_tool_keyword = "4142dd9b827ddda740d7810e94f28d65a9aedeba637b8e3d785dba1947ccad52" nocase ascii wide
                        $string49_macro_pack_offensive_tool_keyword = "524b9d99ab1bd72dd6b227ffc77c539c6abca8d429f56483dae709bc96e445dc" nocase ascii wide
                        $string50_macro_pack_offensive_tool_keyword = "5be6fef49d21ddd81cfd1a8076c04385568d5120f20e0451bf4aaab0796e1656" nocase ascii wide
                        $string51_macro_pack_offensive_tool_keyword = "61693b7ce852af0c5704294658176c64c547fc15401f7730261349340c47dba2" nocase ascii wide
                        $string52_macro_pack_offensive_tool_keyword = "62f8b7689b4e41dd4035f0583ec04493d41f783e7d8152bb4dd4196e3bbc7cf5" nocase ascii wide
                        $string53_macro_pack_offensive_tool_keyword = "6ef90637f19f9be257697a77dada7d97a1655705e821aa4b51eda2eed6e8751f" nocase ascii wide
                        $string54_macro_pack_offensive_tool_keyword = "72eec1e82c566ff08110a4d06cd5b06cc82c67419131ad52fc537ff5552f69ab" nocase ascii wide
                        $string55_macro_pack_offensive_tool_keyword = "80326cd79c767a6230f8b271ac764743b204d6c1af6cf7ac464ba5919f037e0d" nocase ascii wide
                        $string56_macro_pack_offensive_tool_keyword = "96644c680528a212dff1c83615d8ca831fc21060c2dd08790bec98e6294576ee" nocase ascii wide
                        $string57_macro_pack_offensive_tool_keyword = "967f010c2da33a4f2d610ec3bf7125430367e18d2f83baa18fa2b9172fd990ac" nocase ascii wide
                        $string58_macro_pack_offensive_tool_keyword = "972963c83a5b6277233d9c33536b666a296b02137a267f685f7845e0b848d10b" nocase ascii wide
                        $string59_macro_pack_offensive_tool_keyword = "99bedbdf28a0b90732b830ce18672ea3b5367b57bf0366714fefaa5d5e2d46f5" nocase ascii wide
                        $string60_macro_pack_offensive_tool_keyword = "9c03a993cb73874e6e4ecbdd9c8df8b657f4f45395ae342e9206e56d72224d7c" nocase ascii wide
                        $string61_macro_pack_offensive_tool_keyword = "9e9aaf77f76851a8d1da734637ed245260ad503de82fa4c886a070e29fdd3ee3" nocase ascii wide
                        $string62_macro_pack_offensive_tool_keyword = "ac66758a6f95a4ec9aadef67b4bb85dec9aaa8fd98f0f52cbdfe519ac1c78d77" nocase ascii wide
                        $string63_macro_pack_offensive_tool_keyword = "b394dc8dd4e30635b73da61c974d966752ed7712e6a4116b257baee6f7d1718f" nocase ascii wide
                        $string64_macro_pack_offensive_tool_keyword = "b4c70e7499e46ab28c305ce9937933ea2674a16df3686830f6016c9321e23b84" nocase ascii wide
                        $string65_macro_pack_offensive_tool_keyword = "bb8e4578feb7e957ef5b77433c1ee7cb339499d1bd05460848bc841871e0b672" nocase ascii wide
                        $string66_macro_pack_offensive_tool_keyword = "c27a8cb8c4a97bbd0898799f3449d0f0a659360fc56cb43e0755bfeb25939241" nocase ascii wide
                        $string67_macro_pack_offensive_tool_keyword = "C33A0993-A331-406C-83F5-9357DF239B30" nocase ascii wide
                        $string68_macro_pack_offensive_tool_keyword = "c876220ab3ebb8d45afeb7dfc23ca6a0eff57a1e323533352c089768a6c487b6" nocase ascii wide
                        $string69_macro_pack_offensive_tool_keyword = "ca245e03a26fd178305f09c391ee065899ab88dd3de6663b397a84d411f310fc" nocase ascii wide
                        $string70_macro_pack_offensive_tool_keyword = "cmd /c ping localhost -n 1\"" nocase ascii wide
                        $string71_macro_pack_offensive_tool_keyword = "d7792222dd6c580b5590d1cef292b118d7ebbab6570db74cb459ef9f3ee4c1f5" nocase ascii wide
                        $string72_macro_pack_offensive_tool_keyword = "df1d68f681e71e7c78c734a467a4aa7d968c1bb11760868b13d93ffa7f65a0c0" nocase ascii wide
                        $string73_macro_pack_offensive_tool_keyword = "e064a38f4cb8dbe91f3be32c1b2e925c40ceff78ce299bd1e6cf77339def978a" nocase ascii wide
                        $string74_macro_pack_offensive_tool_keyword = "e6449478a32a49ac379f11e0f346267f44f590e777c32902e2bc06903118a69a" nocase ascii wide
                        $string75_macro_pack_offensive_tool_keyword = "e6e7a49af780e80542a3b0e80b9bd524bcb513fa200800f7571112be8f681abb" nocase ascii wide
                        $string76_macro_pack_offensive_tool_keyword = "ea4813fb19c07cb9d7c111c4808fa3eee05e3bf62694bc2481e50465c8853fda" nocase ascii wide
                        $string77_macro_pack_offensive_tool_keyword = /emeric\.nasi\@sevagas\.com/ nocase ascii wide
                        $string78_macro_pack_offensive_tool_keyword = "f22360bb210b78e92b7aecfefb3c0c70e72e81cd03c1afd616e7691a744c3b28" nocase ascii wide
                        $string79_macro_pack_offensive_tool_keyword = "f28955ff3d7997fbac71b4fe7c92a8b537566ace240455a312383792745c3e18" nocase ascii wide
                        $string80_macro_pack_offensive_tool_keyword = "f7dc3c322ee7bb4d5f5b3ee99b8fefb47c6fccda3c112c4b2f4c36eae1a86247" nocase ascii wide
                        $string81_macro_pack_offensive_tool_keyword = "fa9719d556cd1b8b951f7c1f561881c99da7cf41f25c41d8a87fab113144226a" nocase ascii wide
                        $string82_macro_pack_offensive_tool_keyword = /http\:\/\/blog\.sevagas\.com\/\?Hacking\-around\-HTA\-files/ nocase ascii wide
                        $string83_macro_pack_offensive_tool_keyword = /http\:\/\/blog\.sevagas\.com\/\?My\-VBA\-Bot/ nocase ascii wide
                        $string84_macro_pack_offensive_tool_keyword = /https\:\/\/blog\.sevagas\.com\/\?Advanced\-MacroPack\-payloads\-XLM\-Injection/ nocase ascii wide
                        $string85_macro_pack_offensive_tool_keyword = /https\:\/\/blog\.sevagas\.com\/\?Bypass\-Windows\-Defender\-Attack\-Surface\-Reduction/ nocase ascii wide
                        $string86_macro_pack_offensive_tool_keyword = /https\:\/\/blog\.sevagas\.com\/\?EXCEL\-4\-0\-XLM\-macro\-in\-MacroPack\-Pro/ nocase ascii wide
                        $string87_macro_pack_offensive_tool_keyword = /https\:\/\/blog\.sevagas\.com\/\?Launch\-shellcodes\-and\-bypass\-Antivirus\-using\-MacroPack\-Pro\-VBA\-payloads/ nocase ascii wide
                        $string88_macro_pack_offensive_tool_keyword = /macro_pack\.exe\s\-G\s/ nocase ascii wide
                        $string89_macro_pack_offensive_tool_keyword = /mimikatz\.dll/ nocase ascii wide
                        $string90_macro_pack_offensive_tool_keyword = /modules\.obfuscate_strings/ nocase ascii wide
                        $string91_macro_pack_offensive_tool_keyword = /modules\.uac_bypass/ nocase ascii wide
                        $string92_macro_pack_offensive_tool_keyword = "msfvenom -p " nocase ascii wide
                        $string93_macro_pack_offensive_tool_keyword = "REM Generate meterpreter dll payload" nocase ascii wide
                        $string94_macro_pack_offensive_tool_keyword = "sevagas/macro_pack" nocase ascii wide
                        $string95_macro_pack_offensive_tool_keyword = /UACBypassExecuteCMDAsync\.py/ nocase ascii wide
                        $string96_macro_pack_offensive_tool_keyword = /vbLib\.ExecuteCMDAsync/ nocase ascii wide
                        $string97_macro_pack_offensive_tool_keyword = /vbLib\.Meterpreter/ nocase ascii wide
                        $string98_macro_pack_offensive_tool_keyword = /vbLib\.UACBypassExecuteCMDAsync/ nocase ascii wide
                        $string99_macro_pack_offensive_tool_keyword = /vbLib\.WmiExec/ nocase ascii wide
                        $string100_macro_pack_offensive_tool_keyword = /vbLib\.WscriptExec/ nocase ascii wide
                        $string101_macro_pack_offensive_tool_keyword = /wmicexe\-whitelisting\-bypass\-hacking\.html/ nocase ascii wide
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