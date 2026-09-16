rule WEBSHELL_JAVA_VersaMem_JAR_Aug24_2 {
   meta:
      description = "Detects VersaMem Java webshell samples (as used by Volt Typhoon)"
      author = "Florian Roth"
      reference = "https://x.com/craiu/status/1828687700884336990"
      date = "2024-08-29"
      score = 75
      hash1 = "4bcedac20a75e8f8833f4725adfc87577c32990c3783bf6c743f14599a176c37"
      id = "5ca598ed-5d0a-563d-a5e8-f8229af2c949"
   strings:
      $x1 = "tomcat_memShell" ascii
      $x2 = "versa/vnms/ui/config/" ascii fullword
   condition:
      uint16(0) == 0x4b50
      and filesize < 3000KB
      and 1 of them
}