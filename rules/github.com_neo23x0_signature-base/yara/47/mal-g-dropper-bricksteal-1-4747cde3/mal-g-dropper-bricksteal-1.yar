rule MAL_G_Dropper_BRICKSTEAL_1 {
   meta:
      description = "Detects backdoor BRICKSTEAL dropper used by APT group UNC5221 (China Nexus)"
      author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
      date = "2025-09-25"
      score = 75
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
   strings:
      $str1 = "Base64.getDecoder().decode"
      $str2 = "Thread.currentThread().getContextClassLoader()"
      $str3 = ".class.getDeclaredMethod"
      $str4 = "byte[].class"
      $str5 = "method.invoke"
      $str6 = "filterClass.newInstance()"
      $str7 = "/websso/SAML2/SSO/*"
   condition:
      all of them
}