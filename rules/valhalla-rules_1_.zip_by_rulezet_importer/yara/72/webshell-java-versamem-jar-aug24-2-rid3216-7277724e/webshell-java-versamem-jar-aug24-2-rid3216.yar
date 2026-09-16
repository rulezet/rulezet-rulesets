rule WEBSHELL_JAVA_VersaMem_JAR_Aug24_2_RID3216 : DEMO FILE G1017 T1505_003 WEBSHELL {
   meta:
      description = "Detects VersaMem Java webshell samples (as used by Volt Typhoon)"
      author = "Florian Roth"
      reference = "https://x.com/craiu/status/1828687700884336990"
      date = "2024-08-29 13:50:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4bcedac20a75e8f8833f4725adfc87577c32990c3783bf6c743f14599a176c37"
      tags = "DEMO, FILE, G1017, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "tomcat_memShell" ascii
      $x2 = "versa/vnms/ui/config/" ascii fullword
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 3000KB and 1 of them
}