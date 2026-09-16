rule SUSP_WEBSHELL_LOG_Signatures_Dec25 {
   meta:
      description = "Detects indicators related simple webshells that use the same exec/cmd pattern"
      author = "Florian Roth"
      reference = "https://x.com/pyn3rd/status/1996840827897954542/photo/1"
      date = "2025-12-05"
      score = 60
   strings:
      $xa1 = "/exec?cmd=ls"
      $xa2 = "/exec?cmd=whoami"
      $xa3 = "/exec?cmd=id"
      $xa4 = "/exec?cmd=uname%20-a"
   condition:
      1 of them
            and not uint16(0) == 0x3c3f
}