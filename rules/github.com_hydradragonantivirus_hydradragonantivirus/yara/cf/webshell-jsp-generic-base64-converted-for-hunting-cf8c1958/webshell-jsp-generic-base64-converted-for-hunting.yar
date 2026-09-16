rule webshell_jsp_generic_base64__converted_for_hunting: WEBSHELL HUNT_CONVERTED {
  meta:
    key   = "Generic JSP webshell with base64 encoded payload"
    key   = "https://creativecommons.org/licenses/by-nc/4.0/"
    key   = "Arnim Rupp"
    key   = "2021/01/24"
    score = 40

  strings:
    $one1        = "SdW50aW1l" wide ascii
    $one2        = "J1bnRpbW" wide ascii
    $one3        = "UnVudGltZ" wide ascii
    $one4        = "IAdQBuAHQAaQBtAGUA" wide ascii
    $one5        = "SAHUAbgB0AGkAbQBlA" wide ascii
    $one6        = "UgB1AG4AdABpAG0AZQ" wide ascii
    $two1        = "leGVj" wide ascii
    $two2        = "V4ZW" wide ascii
    $two3        = "ZXhlY" wide ascii
    $two4        = "UAeABlAGMA" wide ascii
    $two5        = "lAHgAZQBjA" wide ascii
    $two6        = "ZQB4AGUAYw" wide ascii
    $three1      = "TY3JpcHRFbmdpbmVGYWN0b3J5" wide ascii
    $three2      = "NjcmlwdEVuZ2luZUZhY3Rvcn" wide ascii
    $three3      = "U2NyaXB0RW5naW5lRmFjdG9ye" wide ascii
    $three4      = "MAYwByAGkAcAB0AEUAbgBnAGkAbgBlAEYAYQBjAHQAbwByAHkA" wide ascii
    $three5      = "TAGMAcgBpAHAAdABFAG4AZwBpAG4AZQBGAGEAYwB0AG8AcgB5A" wide ascii
    $three6      = "UwBjAHIAaQBwAHQARQBuAGcAaQBuAGUARgBhAGMAdABvAHIAeQ" wide ascii
    $cjsp_short1 = "<%" ascii wide
    $cjsp_short2 = "%>" wide ascii
    $cjsp_long1  = "<jsp:" ascii wide
    $cjsp_long2  = /language=[\"']java[\"\']/ ascii wide
    $cjsp_long3  = "/jstl/core" ascii wide
    $cjsp_long4  = "<%@p" nocase ascii wide
    $cjsp_long5  = "<%@ " nocase ascii wide
    $cjsp_long6  = "<% " ascii wide
    $cjsp_long7  = "< %" ascii wide
    $dex         = { 64 65 (78 | 79) 0a 30 }
    $pack        = { 50 41 43 4b 00 00 00 02 00 }

  condition:
    ($cjsp_short1 at 0 or any of ($cjsp_long*) or $cjsp_short2 in (filesize - 100..filesize) or
      ($cjsp_short2 and
        ($cjsp_short1 in (0..1000) or $cjsp_short1 in (filesize - 1000..filesize)))) and not (uint16(0) == 0x5a4d or $dex at 0 or $pack at 0 or uint16(0) == 0x4b50) and (filesize >= 300KB and filesize < 900KB
    )
    and
    (any of ($one*) and any of ($two*) or any of ($three*))
}