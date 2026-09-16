rule MAL_G_Backdoor_BRICKSTEAL_1 {
   meta:
      description = "Detects backdoor BRICKSTEAL used by APT group UNC5221 (China Nexus)"
      author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
      date = "2025-09-25"
      score = 75
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
   strings:
      $str1 = "comvmware"
      $str2 = "abcdABCD1234!@#$"
      $str3 = "ads.png"
      $str4 = "User-Agent"
      $str5 = "com/vmware/"
   condition:
      all of them and filesize < 10KB
}