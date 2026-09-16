rule DragonFly_APT_Sep17_2 {
   meta:
      description = "Detects malware from DrqgonFly APT report"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12"
      modified = "2023-01-06"
      hash1 = "178348c14324bc0a3e57559a01a6ae6aa0cb4013aabbe324b51f906dcf5d537e"
      id = "e64f121d-a628-54b5-88f3-96eea388c155"
   strings:
      $s1 = "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Login Data" wide
      $s2 = "C:\\Users\\Public\\Log.txt" fullword wide
      $s3 = "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins" fullword wide
      $s4 = "***************** Mozilla Firefox ****************" fullword wide
      $s5 = "********************** Opera *********************" fullword wide
      $s6 = "\\AppData\\Local\\Microsoft\\Credentials\\" wide
      $s7 = "\\Appdata\\Local\\Google\\Chrome\\User Data\\Default\\" wide
      $s8 = "**************** Internet Explorer ***************" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and 3 of them )
}