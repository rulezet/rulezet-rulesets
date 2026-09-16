rule WEBSHELL_JSP_Generic_Base64
{
    meta:
        description = "Generic JSP webshell with base64 encoded payload"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2025-08-18"
        hash = "8b5fe53f8833df3657ae2eeafb4fd101c05f0db0"
        hash = "1b916afdd415dfa4e77cecf47321fd676ba2184d"

        id = "2eabbad2-7d10-573a-9120-b9b763fa2352"
    strings:
                $one1 = "SdW50aW1l" wide ascii
        $one2 = "J1bnRpbW" wide ascii
        $one3 = "UnVudGltZ" wide ascii
        $one4 = "IAdQBuAHQAaQBtAGUA" wide ascii
        $one5 = "SAHUAbgB0AGkAbQBlA" wide ascii
        $one6 = "UgB1AG4AdABpAG0AZQ" wide ascii
                $two1 = "leGVj" wide ascii
        $two2 = "V4ZW" wide ascii
        $two3 = "ZXhlY" wide ascii
        $two4 = "UAeABlAGMA" wide ascii
        $two5 = "lAHgAZQBjA" wide ascii
        $two6 = "ZQB4AGUAYw" wide ascii
                $three1 = "TY3JpcHRFbmdpbmVGYWN0b3J5" wide ascii
        $three2 = "NjcmlwdEVuZ2luZUZhY3Rvcn" wide ascii
        $three3 = "U2NyaXB0RW5naW5lRmFjdG9ye" wide ascii
        $three4 = "MAYwByAGkAcAB0AEUAbgBnAGkAbgBlAEYAYQBjAHQAbwByAHkA" wide ascii
        $three5 = "TAGMAcgBpAHAAdABFAG4AZwBpAG4AZQBGAGEAYwB0AG8AcgB5A" wide ascii
        $three6 = "UwBjAHIAaQBwAHQARQBuAGcAaQBuAGUARgBhAGMAdABvAHIAeQ" wide ascii


                $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
                $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

                $dex1 = "dex\n0"
        $dex2 = "dey\n0"
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

    condition:
        (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and not (
        uint16(0) == 0x5a4d or
        $dex1 at 0 or
        $dex2 at 0 or
        $pack at 0 or
                uint16(0) == 0x4b50
        )
        and filesize < 300KB and
        ( any of ( $one* ) and any of ( $two* ) or any of ( $three* ) )
}