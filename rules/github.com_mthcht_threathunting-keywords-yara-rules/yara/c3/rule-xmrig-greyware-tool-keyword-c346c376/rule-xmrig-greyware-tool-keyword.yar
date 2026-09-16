rule rule_xmrig_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'xmrig' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xmrig"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_xmrig_greyware_tool_keyword = /\sxmrig\.exe/ nocase ascii wide
                        $string2_xmrig_greyware_tool_keyword = " c3pool_miner" nocase ascii wide
                        $string3_xmrig_greyware_tool_keyword = /\s\-\-coin\s.{0,100}\-\-nicehash\s/ nocase ascii wide
                        $string4_xmrig_greyware_tool_keyword = " --coin=monero" nocase ascii wide
                        $string5_xmrig_greyware_tool_keyword = /\s\-\-config\=.{0,100}c3pool.{0,100}config_background\.json/ nocase ascii wide
                        $string6_xmrig_greyware_tool_keyword = " --donate-level=" nocase ascii wide
                        $string7_xmrig_greyware_tool_keyword = " install c3pool_miner " nocase ascii wide
                        $string8_xmrig_greyware_tool_keyword = /\s\-\-nicehash\s.{0,100}\-\-coin\s/ nocase ascii wide
                        $string9_xmrig_greyware_tool_keyword = " set xmrig Type SERVICE_WIN32_OWN_PROCESS" nocase ascii wide
                        $string10_xmrig_greyware_tool_keyword = /\%USERPROFILE\%\\\\nssm\.zip/ nocase ascii wide
                        $string11_xmrig_greyware_tool_keyword = /\/xmrig\-.{0,100}\-gcc\-win64\.zip/ nocase ascii wide
                        $string12_xmrig_greyware_tool_keyword = /\/xmrig\.exe/ nocase ascii wide
                        $string13_xmrig_greyware_tool_keyword = /\/xmrig\.git/ nocase ascii wide
                        $string14_xmrig_greyware_tool_keyword = /\\c3pool\\\\miner\.bat/ nocase ascii wide
                        $string15_xmrig_greyware_tool_keyword = /\\c3pool\\config\.json/ nocase ascii wide
                        $string16_xmrig_greyware_tool_keyword = /\\WinRing0x64\.sys/ nocase ascii wide
                        $string17_xmrig_greyware_tool_keyword = /\\xmrig\-.{0,100}\-gcc\-win64\.zip/ nocase ascii wide
                        $string18_xmrig_greyware_tool_keyword = /\\xmrig\.exe/ nocase ascii wide
                        $string19_xmrig_greyware_tool_keyword = /\\xmrig\.log/ nocase ascii wide
                        $string20_xmrig_greyware_tool_keyword = /\\xmrig_setup\\/ nocase ascii wide
                        $string21_xmrig_greyware_tool_keyword = /\\xmrig\-6\.20\.0/ nocase ascii wide
                        $string22_xmrig_greyware_tool_keyword = /\\xmrig\-master/ nocase ascii wide
                        $string23_xmrig_greyware_tool_keyword = /\]\sCreating\sc3pool_miner\sservice/ nocase ascii wide
                        $string24_xmrig_greyware_tool_keyword = /\]\sLooking\sfor\sthe\slatest\sversion\sof\sMonero\sminer/ nocase ascii wide
                        $string25_xmrig_greyware_tool_keyword = /\]\sRemoving\sprevious\sc3pool\sminer\s/ nocase ascii wide
                        $string26_xmrig_greyware_tool_keyword = /\]\sRunning\sminer\sin\sthe\sbackground/ nocase ascii wide
                        $string27_xmrig_greyware_tool_keyword = "08384f3f05ad85b2aa935dbd2e46a053cb0001b28bbe593dde2a8c4b822c2a7d" nocase ascii wide
                        $string28_xmrig_greyware_tool_keyword = "0tZG9uYXRlLWxldmVsP" nocase ascii wide
                        $string29_xmrig_greyware_tool_keyword = "3b5cbf0dddc3ef7e3af7d783baef315bf47be6ce11ff83455a2165befe6711f5" nocase ascii wide
                        $string30_xmrig_greyware_tool_keyword = "4fe9647d6a8bf4790df0277283f9874385e0cd05f3008406ca5624aba8d78924" nocase ascii wide
                        $string31_xmrig_greyware_tool_keyword = "5575c76987333427f74263e090910eae45817f0ede6b452d645fd5f9951210c9" nocase ascii wide
                        $string32_xmrig_greyware_tool_keyword = "5a6e7d5c10789763b0b06442dbc7f723f8ea9aec1402abedf439c6801a8d86f2" nocase ascii wide
                        $string33_xmrig_greyware_tool_keyword = "99e3e313b62bb8b55e2637fc14a78adb6f33632a3c722486416252e2630cfdf6" nocase ascii wide
                        $string34_xmrig_greyware_tool_keyword = "C3Pool mining setup script v" nocase ascii wide
                        $string35_xmrig_greyware_tool_keyword = "C3Pool/xmrig_setup" nocase ascii wide
                        $string36_xmrig_greyware_tool_keyword = "c3pool_miner service" nocase ascii wide
                        $string37_xmrig_greyware_tool_keyword = /c3pool_miner\.bat/ nocase ascii wide
                        $string38_xmrig_greyware_tool_keyword = /c3pool_miner\.service/ nocase ascii wide
                        $string39_xmrig_greyware_tool_keyword = /c3pool_miner\.sh/ nocase ascii wide
                        $string40_xmrig_greyware_tool_keyword = /c3pool_miner\\/ nocase ascii wide
                        $string41_xmrig_greyware_tool_keyword = "cpulimit -e xmrig " nocase ascii wide
                        $string42_xmrig_greyware_tool_keyword = "dd7fef5e3594eb18dd676e550e128d4b64cc5a469ff6954a677dc414265db468" nocase ascii wide
                        $string43_xmrig_greyware_tool_keyword = "Description=Monero miner service" nocase ascii wide
                        $string44_xmrig_greyware_tool_keyword = /donate\.ssl\.xmrig\.com/ nocase ascii wide
                        $string45_xmrig_greyware_tool_keyword = /donate\.v2\.xmrig\.com\:3333/ nocase ascii wide
                        $string46_xmrig_greyware_tool_keyword = /donate\.xmrig\.com/ nocase ascii wide
                        $string47_xmrig_greyware_tool_keyword = /Downloading.{0,100}\%MINER_LOCATION\%/ nocase ascii wide
                        $string48_xmrig_greyware_tool_keyword = "e1ff2208b3786cac801ffb470b9475fbb3ced74eb503bfde7aa7f22af113989d" nocase ascii wide
                        $string49_xmrig_greyware_tool_keyword = /fee\.xmrig\.com/ nocase ascii wide
                        $string50_xmrig_greyware_tool_keyword = "ff6e67d725ee64b4607dc6490a706dc9234c708cff814477de52d3beb781c6a1" nocase ascii wide
                        $string51_xmrig_greyware_tool_keyword = /github.{0,100}\/xmrig\/xmrig/ nocase ascii wide
                        $string52_xmrig_greyware_tool_keyword = /gpg_keys\/xmrig\.asc/ nocase ascii wide
                        $string53_xmrig_greyware_tool_keyword = /https\:\/\/c3pool\.com\/\#\// nocase ascii wide
                        $string54_xmrig_greyware_tool_keyword = "killall xmrig" nocase ascii wide
                        $string55_xmrig_greyware_tool_keyword = "LS1kb25hdGUtbGV2ZWw9"
                        $string56_xmrig_greyware_tool_keyword = "mining in background will be started using your startup directory script and only work when your are logged in this host" nocase ascii wide
                        $string57_xmrig_greyware_tool_keyword = /Mining\swill\shappen\sto\s.{0,100}\swallet/ nocase ascii wide
                        $string58_xmrig_greyware_tool_keyword = "Monero miner is already running in the background" nocase ascii wide
                        $string59_xmrig_greyware_tool_keyword = "nssm set xmrig AppNoConsole 1" nocase ascii wide
                        $string60_xmrig_greyware_tool_keyword = /offline_miner_setup\.zip/ nocase ascii wide
                        $string61_xmrig_greyware_tool_keyword = /randomx\.xmrig\.com/ nocase ascii wide
                        $string62_xmrig_greyware_tool_keyword = "set xmrig start" nocase ascii wide
                        $string63_xmrig_greyware_tool_keyword = "setup and run in background Monero CPU miner" nocase ascii wide
                        $string64_xmrig_greyware_tool_keyword = /solo_mine_example\.cmd/ nocase ascii wide
                        $string65_xmrig_greyware_tool_keyword = /src\/xmrig\.cpp/ nocase ascii wide
                        $string66_xmrig_greyware_tool_keyword = /src\\xmrig\.cpp/ nocase ascii wide
                        $string67_xmrig_greyware_tool_keyword = "start doing stuff: preparing miner" nocase ascii wide
                        $string68_xmrig_greyware_tool_keyword = /support\@c3pool\.com/ nocase ascii wide
                        $string69_xmrig_greyware_tool_keyword = /WinRing0.{0,100}WinRing0x64\.sys/ nocase ascii wide
                        $string70_xmrig_greyware_tool_keyword = /xmrig\-.{0,100}\-bionic\-x64\.tar\.gz/ nocase ascii wide
                        $string71_xmrig_greyware_tool_keyword = /xmrig\-.{0,100}\-focal\-x64\.tar\.gz/ nocase ascii wide
                        $string72_xmrig_greyware_tool_keyword = /xmrig\-.{0,100}\-freebsd\-static\-x64\.tar\.gz/ nocase ascii wide
                        $string73_xmrig_greyware_tool_keyword = /xmrig\-.{0,100}\-gcc\-win64\.zip/ nocase ascii wide
                        $string74_xmrig_greyware_tool_keyword = /xmrig\-.{0,100}\-linux\-static\-x64\.tar\.gz/
                        $string75_xmrig_greyware_tool_keyword = /xmrig\-.{0,100}\-linux\-x64\.tar\.gz/
                        $string76_xmrig_greyware_tool_keyword = /xmrig\-.{0,100}\-macos\-arm64\.tar\.gz/ nocase ascii wide
                        $string77_xmrig_greyware_tool_keyword = /xmrig\-.{0,100}\-macos\-x64\.tar\.gz/ nocase ascii wide
                        $string78_xmrig_greyware_tool_keyword = /xmrig\-.{0,100}\-msvc\-win64\.zip/ nocase ascii wide
                        $string79_xmrig_greyware_tool_keyword = /xmrig\.exe\s\-/ nocase ascii wide
                        $string80_xmrig_greyware_tool_keyword = /xmrig\.service/ nocase ascii wide
                        $string81_xmrig_greyware_tool_keyword = /xmrig\.tar\.gz/ nocase ascii wide
                        $string82_xmrig_greyware_tool_keyword = /xmrig\.zip/ nocase ascii wide
                        $string83_xmrig_greyware_tool_keyword = /xmrminer\.cc/ nocase ascii wide
                        $string84_xmrig_greyware_tool_keyword = /xmrpool\.de/ nocase ascii wide
                        $string85_xmrig_greyware_tool_keyword = /xmrpool\.eu/ nocase ascii wide
                        $string86_xmrig_greyware_tool_keyword = /xmrpool\.eu\:3333/ nocase ascii wide
                        $string87_xmrig_greyware_tool_keyword = /xmrpool\.me/ nocase ascii wide
                        $string88_xmrig_greyware_tool_keyword = /xmrpool\.net/ nocase ascii wide
                        $string89_xmrig_greyware_tool_keyword = /xmrpool\.xyz/ nocase ascii wide
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