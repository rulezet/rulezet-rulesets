rule WEBSHELL_ASPX_ProxyShell_Aug21_3_RID31EC : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be DER), size and content"
      author = "Max Altgelt"
      reference = "https://twitter.com/gossithedog/status/1429175908905127938?s=12"
      date = "2021-08-23 13:43:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Page Language=" ascii nocase
   condition: 
      uint16 ( 0 ) == 0x8230 and filesize < 10KB and $s1
}