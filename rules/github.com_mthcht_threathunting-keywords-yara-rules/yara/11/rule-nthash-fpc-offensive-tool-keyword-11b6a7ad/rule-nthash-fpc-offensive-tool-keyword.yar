rule rule_NTHASH_FPC_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NTHASH-FPC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTHASH-FPC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NTHASH_FPC_offensive_tool_keyword = /\s\/changentlm.{0,1000}\s\/user\:.{0,1000}\s\/oldhash\:/ nocase ascii wide
                        $string2_NTHASH_FPC_offensive_tool_keyword = /\s\/changentlm.{0,1000}\s\/user\:.{0,1000}\s\/oldpwd\:/ nocase ascii wide
                        $string3_NTHASH_FPC_offensive_tool_keyword = /\s\/changentlm.{0,1000}\s\/user\:.{0,1000}\s\/oldpwd\:/ nocase ascii wide
                        $string4_NTHASH_FPC_offensive_tool_keyword = /\s\/decodemk\s\/binary\:.{0,1000}\s\/password\:/ nocase ascii wide
                        $string5_NTHASH_FPC_offensive_tool_keyword = /\s\/dumpsecret\s\/input\:.{0,1000}\s\/system/ nocase ascii wide
                        $string6_NTHASH_FPC_offensive_tool_keyword = " /dumpsecret /input:defaultpassword" nocase ascii wide
                        $string7_NTHASH_FPC_offensive_tool_keyword = " /dumpsecret /input:dpapi_system /offline" nocase ascii wide
                        $string8_NTHASH_FPC_offensive_tool_keyword = /\s\/gethmac\s\/mode\:hashid\s\/input\:.{0,1000}\s\/key\:/ nocase ascii wide
                        $string9_NTHASH_FPC_offensive_tool_keyword = " /getlsasecret /input:" nocase ascii wide
                        $string10_NTHASH_FPC_offensive_tool_keyword = " /getntlmhash /password:" nocase ascii wide
                        $string11_NTHASH_FPC_offensive_tool_keyword = /\s\/getntlmhash\s\|\swtee\s.{0,1000}\.ntlm/ nocase ascii wide
                        $string12_NTHASH_FPC_offensive_tool_keyword = " /getsamkey /offline" nocase ascii wide
                        $string13_NTHASH_FPC_offensive_tool_keyword = /\s\/ptt\s\/binary\:.{0,1000}\.kirbi/ nocase ascii wide
                        $string14_NTHASH_FPC_offensive_tool_keyword = /\s\/setntlm\s.{0,1000}\s\/user\:.{0,1000}\s\/newhash\:/ nocase ascii wide
                        $string15_NTHASH_FPC_offensive_tool_keyword = /\s\/setntlm\s.{0,1000}\s\/user\:.{0,1000}\s\/newpwd\:/ nocase ascii wide
                        $string16_NTHASH_FPC_offensive_tool_keyword = /\sby\serwan2212\@gmail\.com/ nocase ascii wide
                        $string17_NTHASH_FPC_offensive_tool_keyword = /\snc_srv\.bat/ nocase ascii wide
                        $string18_NTHASH_FPC_offensive_tool_keyword = /\srevshell32\.bin/ nocase ascii wide
                        $string19_NTHASH_FPC_offensive_tool_keyword = /\srevshell64\.bin/ nocase ascii wide
                        $string20_NTHASH_FPC_offensive_tool_keyword = /\.exe\s\s\/logonpasswords\s\/symbol/ nocase ascii wide
                        $string21_NTHASH_FPC_offensive_tool_keyword = /\.exe\s\/gethmac\s\/mode\:SHA1\s\/key\:/ nocase ascii wide
                        $string22_NTHASH_FPC_offensive_tool_keyword = /\/nc_srv\.bat/ nocase ascii wide
                        $string23_NTHASH_FPC_offensive_tool_keyword = /\/NTHASH\-FPC\.git/ nocase ascii wide
                        $string24_NTHASH_FPC_offensive_tool_keyword = /\/revshell32\.bin/ nocase ascii wide
                        $string25_NTHASH_FPC_offensive_tool_keyword = /\/revshell64\.bin/ nocase ascii wide
                        $string26_NTHASH_FPC_offensive_tool_keyword = /\\amsi\\dll\.zip/ nocase ascii wide
                        $string27_NTHASH_FPC_offensive_tool_keyword = /\\amsi\\hook\-win32\.dll/ nocase ascii wide
                        $string28_NTHASH_FPC_offensive_tool_keyword = /\\amsi\\hook\-win64\.dll/ nocase ascii wide
                        $string29_NTHASH_FPC_offensive_tool_keyword = /\\DumpSomeHashesAuto\.py/ nocase ascii wide
                        $string30_NTHASH_FPC_offensive_tool_keyword = /\\nc_srv\.bat/ nocase ascii wide
                        $string31_NTHASH_FPC_offensive_tool_keyword = /\\NTHASH\-FPC\\/ nocase ascii wide
                        $string32_NTHASH_FPC_offensive_tool_keyword = /\\revshell32\.bin/ nocase ascii wide
                        $string33_NTHASH_FPC_offensive_tool_keyword = /\\revshell64\.bin/ nocase ascii wide
                        $string34_NTHASH_FPC_offensive_tool_keyword = /\\wmiexec\.zip/ nocase ascii wide
                        $string35_NTHASH_FPC_offensive_tool_keyword = "_KIWI_BCRYPT_HANDLE_KEY" nocase ascii wide
                        $string36_NTHASH_FPC_offensive_tool_keyword = "_KIWI_BCRYPT_KEY" nocase ascii wide
                        $string37_NTHASH_FPC_offensive_tool_keyword = "_KIWI_BCRYPT_KEY81" nocase ascii wide
                        $string38_NTHASH_FPC_offensive_tool_keyword = "_KIWI_MASTERKEY_CACHE_ENTRY" nocase ascii wide
                        $string39_NTHASH_FPC_offensive_tool_keyword = "_NT6_CLEAR_SECRET" nocase ascii wide
                        $string40_NTHASH_FPC_offensive_tool_keyword = "62f11b4ae2f0d26ed55efd4c918cfec1bd95036f507cf2dbf3295949831366ca" nocase ascii wide
                        $string41_NTHASH_FPC_offensive_tool_keyword = "69ace7287faa4854605ab46018d92332ba0d16ff926ebf17330359a4dbd7d693" nocase ascii wide
                        $string42_NTHASH_FPC_offensive_tool_keyword = "76c7648f79cc5a78f49e9ca24b26a82348e0292b3676ae04bdf22a88cb7eeadc" nocase ascii wide
                        $string43_NTHASH_FPC_offensive_tool_keyword = "806ffe052652b8848d19fe26c63ecc35742077d87bbe04102b048a7c9c644c22" nocase ascii wide
                        $string44_NTHASH_FPC_offensive_tool_keyword = "862f7ba58bbf77543812637ecc32d277fce062d21bc97587e5816e8fb05634e3" nocase ascii wide
                        $string45_NTHASH_FPC_offensive_tool_keyword = "8bb972b4dc7e0c5b8db0be349ecf62043e69ea1273d5298f8e55c02fa047712c" nocase ascii wide
                        $string46_NTHASH_FPC_offensive_tool_keyword = "91502e94bd83b8803e91d20d1b231c112d65561f588b92e888982f7753374e8d" nocase ascii wide
                        $string47_NTHASH_FPC_offensive_tool_keyword = "bHNhc3MuZXhl" nocase ascii wide
                        $string48_NTHASH_FPC_offensive_tool_keyword = /c\:\\temp\\nc\.exe/ nocase ascii wide
                        $string49_NTHASH_FPC_offensive_tool_keyword = "c96ef7d84ab7d43b03330daf4e78c11aa9407662f4a18d1824fa1506694c8c56" nocase ascii wide
                        $string50_NTHASH_FPC_offensive_tool_keyword = "check that our dll as been injected : NTHASH" nocase ascii wide
                        $string51_NTHASH_FPC_offensive_tool_keyword = "e685904d607a73c1916b6a7d9cc2eb42e4afd1cf2e77e728b7dbeb141eda2735" nocase ascii wide
                        $string52_NTHASH_FPC_offensive_tool_keyword = "erwan2212/NTHASH-FPC" nocase ascii wide
                        $string53_NTHASH_FPC_offensive_tool_keyword = /Execute\(\'SELECT\sorigin_url\,username_value\,password_value\,length\(password_value/ nocase ascii wide
                        $string54_NTHASH_FPC_offensive_tool_keyword = "f56f11c598a47a0313a3f4e0929a45a6ed7529119189d7434fbe39721e190083" nocase ascii wide
                        $string55_NTHASH_FPC_offensive_tool_keyword = /For\sfun\sand\s\(no\)\sprofit\s\:\slets\shook\srtlcomparememory\sin\slsass\.exe/ nocase ascii wide
                        $string56_NTHASH_FPC_offensive_tool_keyword = /go\sthru\seach\sline\sin\spasswords\.lst/ nocase ascii wide
                        $string57_NTHASH_FPC_offensive_tool_keyword = /hello\s\%3e\sc\:\\\\temp\\\\test\.txt/ nocase ascii wide
                        $string58_NTHASH_FPC_offensive_tool_keyword = /https\:\/\/erwan2212\.github\.io\/NTHASH\-FPC/ nocase ascii wide
                        $string59_NTHASH_FPC_offensive_tool_keyword = /https\:\/\/hashtoolkit\.com\/generate\-hash\/\?text\=/ nocase ascii wide
                        $string60_NTHASH_FPC_offensive_tool_keyword = "KIWI_KERBEROS_BUFFER" nocase ascii wide
                        $string61_NTHASH_FPC_offensive_tool_keyword = /kuhl_m_dpapi_chrome\.c/ nocase ascii wide
                        $string62_NTHASH_FPC_offensive_tool_keyword = /kuhl_m_lsadump\.c/ nocase ascii wide
                        $string63_NTHASH_FPC_offensive_tool_keyword = /kuhl_m_sekurlsa_utils\.c/ nocase ascii wide
                        $string64_NTHASH_FPC_offensive_tool_keyword = /nc64\s127\.0\.0\.1\s9000\s\-e\scmd\.exe/ nocase ascii wide
                        $string65_NTHASH_FPC_offensive_tool_keyword = "nc64 -L -vv -p 9000" nocase ascii wide
                        $string66_NTHASH_FPC_offensive_tool_keyword = "NTHASH /enumproc " nocase ascii wide
                        $string67_NTHASH_FPC_offensive_tool_keyword = "NTHASH /runas " nocase ascii wide
                        $string68_NTHASH_FPC_offensive_tool_keyword = "NTHASH /runaschild /pid" nocase ascii wide
                        $string69_NTHASH_FPC_offensive_tool_keyword = "NTHASH /runastoken " nocase ascii wide
                        $string70_NTHASH_FPC_offensive_tool_keyword = "NTHASH /runwmi " nocase ascii wide
                        $string71_NTHASH_FPC_offensive_tool_keyword = /NTHASH.{0,1000}\s\/cryptunprotectdata\s\/binary\:/ nocase ascii wide
                        $string72_NTHASH_FPC_offensive_tool_keyword = /NTHASH.{0,1000}\s\/cryptunprotectdata\s\/input\:/ nocase ascii wide
                        $string73_NTHASH_FPC_offensive_tool_keyword = /NTHASH.{0,1000}\s\/dumpsam/ nocase ascii wide
                        $string74_NTHASH_FPC_offensive_tool_keyword = /NTHASH.{0,1000}\s\/enumcred/ nocase ascii wide
                        $string75_NTHASH_FPC_offensive_tool_keyword = /NTHASH.{0,1000}\s\/enumvault/ nocase ascii wide
                        $string76_NTHASH_FPC_offensive_tool_keyword = /NTHASH.{0,1000}\s\/getlsakeys/ nocase ascii wide
                        $string77_NTHASH_FPC_offensive_tool_keyword = /NTHASH.{0,1000}\s\/wlansvc\s\/binary\:/ nocase ascii wide
                        $string78_NTHASH_FPC_offensive_tool_keyword = /NTHASH\-win32\.exe/ nocase ascii wide
                        $string79_NTHASH_FPC_offensive_tool_keyword = /NTHASH\-win64\.exe/ nocase ascii wide
                        $string80_NTHASH_FPC_offensive_tool_keyword = /offlinereg\-win32\.exe/ nocase ascii wide
                        $string81_NTHASH_FPC_offensive_tool_keyword = /offlinereg\-win64\.exe/ nocase ascii wide
                        $string82_NTHASH_FPC_offensive_tool_keyword = /reg\.exe\squery\shklm\\security\\policy\\secrets/ nocase ascii wide
                        $string83_NTHASH_FPC_offensive_tool_keyword = "rem call nthash-win64 /getntlmhash" nocase ascii wide
                        $string84_NTHASH_FPC_offensive_tool_keyword = /rem\scheap\sbruteforce\s\.\.\.\svery\sslow\s\.\.\.\sok\sfor\sa\sfew\spasswords/ nocase ascii wide
                        $string85_NTHASH_FPC_offensive_tool_keyword = "THASH /runts /user:" nocase ascii wide
                        $string86_NTHASH_FPC_offensive_tool_keyword = /toto\s\%3e\sc\:\\\\temp\\\\toto\.txt/ nocase ascii wide

    condition:
        any of them
}