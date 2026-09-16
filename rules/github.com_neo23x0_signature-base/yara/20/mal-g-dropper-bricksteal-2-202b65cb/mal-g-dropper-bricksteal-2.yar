rule MAL_G_Dropper_BRICKSTEAL_2 {
   meta:
      description = "Detects backdoor BRICKSTEAL dropper used by APT group UNC5221 (China Nexus)"
      author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
      date = "2025-09-25"
      score = 75
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
   strings:
            $str1_alt = "(Class<?>) method.invoke(" ascii wide
      $str2 = "(\"yv66vg" ascii wide
      $str3 = "request.getSession().getServletContext" ascii wide
      $str4 = ".getClass().getDeclaredField(" ascii wide
      $str5 = "new FilterDef();" ascii wide
      $str6 = "new FilterMap();" ascii wide
   condition:
      all of them
}