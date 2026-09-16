rule MAL_APT_NK_Andariel_SocksTroy_Strings_OpCodes {
   meta:
      author = "CISA.gov"
      description = "Detects a variant of the SocksTroy malware family"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "9e7fb6ba-771e-5cae-a0d5-c0b95ee6d4e9"
   strings:
      $strHost = "-host" wide
      $strAuth = "-auth" wide
      $SocksTroy = "SocksTroy" 
      $cOpCodeCheck = { 81 E? A0 00 00 00 0F 84 ?? ?? ?? ?? 83 E? 03 74 ?? 83 E? 02 74 ?? 83 F? 0B }
   condition:
      uint16(0) == 0x5a4d and (
         1 of ($str*) 
         and all of ($c*) 
         or all of ($Socks*)
      )
}