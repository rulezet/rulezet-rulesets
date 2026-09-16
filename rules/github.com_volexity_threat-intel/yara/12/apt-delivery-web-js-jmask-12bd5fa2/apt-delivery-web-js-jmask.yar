rule apt_delivery_web_js_jmask: EvilBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the JMASK profiling script in its minified // obfuscated format."
        date = "2023-06-15"
        hash1 = "efea95720853e0cd2d9d4e93a64a726cfe17efea7b17af7c4ae6d3a6acae5b30"
        scan_context = "file"
        last_modified = "2023-09-21T09:38Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $rev0 = "oi.buhtig.ralue//:ptth" ascii
        $rev1 = "lairA' xp41" ascii
        $rev2 = "dnuof ton ksaMateM" ascii

        $unicode1 = "document[\"\\u0063\\u0075\\u0072\\u0072\\u0065\\u006e\\u0074\\u0053\\u0063\\u0072\\u0069\\u0070\\u0074\"]" ascii
        $unicode2 = "\\u0061\\u0070\\u0070\\u006c\\u0069\\u0063\\u0061\\u0074\\u0069\\u006f\\u006e\\u002f\\u006a\\u0073\\u006f\\u006e" ascii
        $unicode3 = "\\u0063\\u006c\\u0069\\u0065\\u006e\\u0074\\u0057\\u0069\\u0064\\u0074\\u0068" ascii
        $unicode4 = "=window[\"\\u0073\\u0063\\u0072\\u0065\\u0065\\u006e\"]" ascii

        $header = "(function(){info={};finished=" ascii
    condition:
        all of ($rev*) or
        all of ($unicode*) or
        $header
}