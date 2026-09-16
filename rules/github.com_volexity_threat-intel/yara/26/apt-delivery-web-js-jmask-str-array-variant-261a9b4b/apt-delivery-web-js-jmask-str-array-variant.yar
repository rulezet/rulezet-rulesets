rule apt_delivery_web_js_jmask_str_array_variant: EvilBamboo
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-06-27"
        description = "Detects the JMASK profiling script in an obfuscated format using a string array and an offset."
        hash1 = "7995c382263f8dbbfc37a9d62392aef8b4f89357d436b3dd94dea842f9574ecf"
        scan_context = "file"
        last_modified = "2023-09-21T09:38Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $array_1 = "http://eular.github.io"
        $array_2 = "stun:stun.services.mozilla.com"
        $array_3 = "\xE6\x9C\xAA\xE5\xAE\x89\xE8\xA3\x85MetaMask"
        $array_4 = "/jquery/jquery.min.js"
        $array_5 = "onicecandidate"

        $ios_1 = "['a7', '640x1136', [_0x"
        $ios_2 = "['a7', _0x"
        $ios_3 = "['a8', _0x"
        $ios_4 = "['a8', '750x1334', ['iPhone\\x206']]"
        $ios_5 = "['a8', '1242x2208', ['iPhone\\x206\\x20Plus']]"
        $ios_6 = "['a8', _0x"
        $ios_7 = "['a9', _0x"
        $ios_8 = "['a9', '750x1334', [_0x"
        $ios_9 = "['a9', '1242x2208', ['iPhone\\x206s\\x20Plus']]"
        $ios_10 = "['a9x', '2048x2732', ['iPad\\x20Pro\\x20(1st\\x20gen\\x2012.9-inch)']]"
        $ios_11 = "['a10x', '1668x2224', [_0x"

        $header = "info = {}, finished = 0x0;"

    condition:
        3 of ($array_*) or
        5 of ($ios_*) or
        $header
}