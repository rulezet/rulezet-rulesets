rule WEBSHELL_G_APT_BackdoorWebshell_SLAYSTYLE_1 {
   meta:
      description = "Detects webshell used by APT group UNC5221 (China Nexus)"
      author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
      date = "2025-09-25"
      score = 75
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
   strings:
            $str1_alt = "=request.getParameter(\""
      $str2 = "=new String(java.util.Base64.getDecoder().decode(" ascii wide nocase
            $str21_alt = "={\"/bin/sh\",\"-c\"," ascii
      $str3 = "= Runtime.getRuntime().exec(" ascii
      $str4 = "java.io.InputStream" ascii
      $str5 = "java.util.Base64.getEncoder().encodeToString(org.apache.commons.io.IOUtils.toByteArray(" ascii
   condition:
      filesize < 5MB and all of them
}