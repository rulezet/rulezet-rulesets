rule rule_merlin_agent_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'merlin-agent' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "merlin-agent"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_merlin_agent_offensive_tool_keyword = /\slink\ssmb\s.{0,100}\smerlinPipe/ nocase ascii wide
                        $string2_merlin_agent_offensive_tool_keyword = /\s\-o\smerlin\.dll\smerlin\.c\s/ nocase ascii wide
                        $string3_merlin_agent_offensive_tool_keyword = "/app/bin/merlinAgent"
                        $string4_merlin_agent_offensive_tool_keyword = /\/c2endpoint\.php/ nocase ascii wide
                        $string5_merlin_agent_offensive_tool_keyword = /\/merlinAgent\-.{0,100}\.exe/ nocase ascii wide
                        $string6_merlin_agent_offensive_tool_keyword = /\/merlin\-agent\.git/ nocase ascii wide
                        $string7_merlin_agent_offensive_tool_keyword = "/merlin-agent/tarball/v" nocase ascii wide
                        $string8_merlin_agent_offensive_tool_keyword = "/merlin-agent/v2/cli" nocase ascii wide
                        $string9_merlin_agent_offensive_tool_keyword = "/merlin-agent/v2/core" nocase ascii wide
                        $string10_merlin_agent_offensive_tool_keyword = "/merlin-agent/zipball/v" nocase ascii wide
                        $string11_merlin_agent_offensive_tool_keyword = "/merlinAgent-Linux-x64"
                        $string12_merlin_agent_offensive_tool_keyword = "/usr/bin/merlinAgent"
                        $string13_merlin_agent_offensive_tool_keyword = /\\\\\.\\pipe\\merlin/ nocase ascii wide
                        $string14_merlin_agent_offensive_tool_keyword = /\\\\\\\\\.\\\\pipe\\\\merlin/ nocase ascii wide
                        $string15_merlin_agent_offensive_tool_keyword = /\\merlinAgent\-.{0,100}\.exe/ nocase ascii wide
                        $string16_merlin_agent_offensive_tool_keyword = /\\merlin\-agent\\.{0,100}\.go/ nocase ascii wide
                        $string17_merlin_agent_offensive_tool_keyword = /\\merlin\-agent\-dll/ nocase ascii wide
                        $string18_merlin_agent_offensive_tool_keyword = /\\os\\windows\\pkg\\evasion\\evasion/ nocase ascii wide
                        $string19_merlin_agent_offensive_tool_keyword = /\\services\\p2p\\p2p\.go/ nocase ascii wide
                        $string20_merlin_agent_offensive_tool_keyword = /127\.0\.0\.1\:7777/ nocase ascii wide
                        $string21_merlin_agent_offensive_tool_keyword = "21fd88a16e0aa75cc0d7e4f814cbb33e57de921ab5648f94a949318023fdec7d" nocase ascii wide
                        $string22_merlin_agent_offensive_tool_keyword = "269ede3b8c442b06d71872f817438e42d9184d58598e11163ff7227c2fe7513e" nocase ascii wide
                        $string23_merlin_agent_offensive_tool_keyword = "98a6c8b05256efdf08b252f191b7fefbc76486301fca678a442d2a9ef6393650" nocase ascii wide
                        $string24_merlin_agent_offensive_tool_keyword = "9cf730bd8182e8ecc74d6f02dc2eba4dc40d1b50effa30941b522010513baeb6" nocase ascii wide
                        $string25_merlin_agent_offensive_tool_keyword = "ad8aa2a15aa507d1d9231c4c5ebaa93501fe32c56d287e83c8f7197d4e15b546" nocase ascii wide
                        $string26_merlin_agent_offensive_tool_keyword = /ADDR\s\?\=\s127\.0\.0\.1\:4444/ nocase ascii wide
                        $string27_merlin_agent_offensive_tool_keyword = "Authenticated returns if the Agent is authenticated to the Merlin server or not" nocase ascii wide
                        $string28_merlin_agent_offensive_tool_keyword = "B11F13DC6E6546E134FE8F836C13CCBBD1D8E5120FBD2B40A81E66DFD7C4EBC3" nocase ascii wide
                        $string29_merlin_agent_offensive_tool_keyword = "bin/merlinAgent" nocase ascii wide
                        $string30_merlin_agent_offensive_tool_keyword = "c36e5e59c3faf245d1cbeb5bf81bdee52eb7d49ff777813e45b33390575072bf" nocase ascii wide
                        $string31_merlin_agent_offensive_tool_keyword = "cbf03e162816e6ba6863355f82b4e9e9853f529d11aa95141fc59781496f8e65" nocase ascii wide
                        $string32_merlin_agent_offensive_tool_keyword = "d0d03a0ae4722535a0e1d5d0c8385ce42015511e68d960fadef4b4eaf5942feb" nocase ascii wide
                        $string33_merlin_agent_offensive_tool_keyword = /DllInstall\sis\sused\swhen\sexecuting\sthe\sMerlin\sagent\swith\sregsvr32\.exe/ nocase ascii wide
                        $string34_merlin_agent_offensive_tool_keyword = /docker\sbuild\s\-t\smerlin\-agent\:.{0,100}\-linux/
                        $string35_merlin_agent_offensive_tool_keyword = /docs\.mythic\-c2\.net/ nocase ascii wide
                        $string36_merlin_agent_offensive_tool_keyword = "fed31f6b45974dfe2f4edc4a180cb44b44caad65e872aa6c656db1d7d3729608" nocase ascii wide
                        $string37_merlin_agent_offensive_tool_keyword = "Input Merlin message base:" nocase ascii wide
                        $string38_merlin_agent_offensive_tool_keyword = "MAGENT=merlinAgent" nocase ascii wide
                        $string39_merlin_agent_offensive_tool_keyword = "merlinAgent-Darwin-x64-"
                        $string40_merlin_agent_offensive_tool_keyword = /merlinAgent\-Darwin\-x64\./
                        $string41_merlin_agent_offensive_tool_keyword = "merlinAgent-Linux-x64-"
                        $string42_merlin_agent_offensive_tool_keyword = /merlinAgent\-Linux\-x64\./
                        $string43_merlin_agent_offensive_tool_keyword = "merlinAgent-Windows-x64-" nocase ascii wide
                        $string44_merlin_agent_offensive_tool_keyword = /merlinAgent\-Windows\-x64\./ nocase ascii wide
                        $string45_merlin_agent_offensive_tool_keyword = /merlinAgent\-Windows\-x64\.exe/ nocase ascii wide
                        $string46_merlin_agent_offensive_tool_keyword = /merlinAgent\-Windows\-x86\.exe/ nocase ascii wide
                        $string47_merlin_agent_offensive_tool_keyword = /merlin\-c2\.readthedocs\.io/ nocase ascii wide
                        $string48_merlin_agent_offensive_tool_keyword = /merlinHTTP\.HTTP/ nocase ascii wide
                        $string49_merlin_agent_offensive_tool_keyword = /merlinHTTP\.JA3/ nocase ascii wide
                        $string50_merlin_agent_offensive_tool_keyword = /merlinHTTP\.PARROT/ nocase ascii wide
                        $string51_merlin_agent_offensive_tool_keyword = /merlinHTTP\.WINHTTP/ nocase ascii wide
                        $string52_merlin_agent_offensive_tool_keyword = /merlinHTTP\.WININET/ nocase ascii wide
                        $string53_merlin_agent_offensive_tool_keyword = "Ne0nd0g/merlin-agent" nocase ascii wide
                        $string54_merlin_agent_offensive_tool_keyword = "r00t0v3rr1d3/merlin" nocase ascii wide
                        $string55_merlin_agent_offensive_tool_keyword = "Received Mythic SOCKS task: " nocase ascii wide
                        $string56_merlin_agent_offensive_tool_keyword = /rundll32\smerlin\.dll\,Magic/ nocase ascii wide
                        $string57_merlin_agent_offensive_tool_keyword = /rundll32\smerlin\.dll\,Merlin/ nocase ascii wide
                        $string58_merlin_agent_offensive_tool_keyword = /rundll32\smerlin\.dll\,Run/ nocase ascii wide
                        $string59_merlin_agent_offensive_tool_keyword = /rundll32\.exe.{0,100}\smerlin\.dll\,Magic/ nocase ascii wide
                        $string60_merlin_agent_offensive_tool_keyword = /rundll32\.exe.{0,100}\smerlin\.dll\,Merlin/ nocase ascii wide
                        $string61_merlin_agent_offensive_tool_keyword = /rundll32\.exe.{0,100}\smerlin\.dll\,Run/ nocase ascii wide
                        $string62_merlin_agent_offensive_tool_keyword = /russel\.vantuyl\@gmail\.com/ nocase ascii wide
                        $string63_merlin_agent_offensive_tool_keyword = /services\/p2p\.Handle\(\)\:\sWrote\sSMB\sfragment\s/ nocase ascii wide
                        $string64_merlin_agent_offensive_tool_keyword = "SetInitialCheckIn updates the time stamp that the Agent first successfully connected to the Merlin server" nocase ascii wide
                        $string65_merlin_agent_offensive_tool_keyword = "SetStatusCheckIn updates the last time the Agent successfully communicated with the Merlin server" nocase ascii wide
                        $string66_merlin_agent_offensive_tool_keyword = "unknown mythic client configuration setting: " nocase ascii wide
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