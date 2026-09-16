rule WEBSHELL_ASPX_ProxyShell_Aug21_3 {
   meta:
      description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be DER), size and content"
      author = "Max Altgelt"
      reference = "https://twitter.com/gossithedog/status/1429175908905127938?s=12"
      date = "2021-08-23"
      score = 75
      id = "a7bca62b-c8f1-5a38-81df-f3d4582a590b"
   strings:
      $s1 = "Page Language=" ascii nocase
   condition:
      uint16(0) == 0x8230  
      and filesize < 10KB
      and $s1
}