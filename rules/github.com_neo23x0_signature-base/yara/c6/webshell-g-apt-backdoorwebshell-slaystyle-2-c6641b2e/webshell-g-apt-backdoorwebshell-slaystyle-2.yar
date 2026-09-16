rule WEBSHELL_G_APT_BackdoorWebshell_SLAYSTYLE_2 {
   meta:
      description = "Detects webshell used by APT group UNC5221 (China Nexus)"
      author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
      date = "2025-09-25"
      score = 75
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
   strings:
      $str1 = "request.getParameter"
      $str2 = "/bin/sh"
      $str3 = "java.io.InputStream"
      $str4 = "Runtime.getRuntime().exec("
      $str5 = "2>&1"
   condition:
      (uint16(0) != 0x5A4D and uint32(0) != 0x464C457F) and filesize < 7KB and all of them and @str4 > @str2
}