rule MAL_Unknown_Discord_Characteristics_Jan22_1 {
   meta:
      description = "Detects unknown malware with a few indicators also found in Wiper malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/"
      date = "2022-01-16"
      score = 75
      hash1 = "dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78"
      id = "23ee5319-6a72-517b-8ea0-55063b6b862c"
   strings:
      $x1 = "xownxloxadDxatxxax" wide
      
      $s2 = "https://cdn.discordapp.com/attachments/" wide
   condition:
      uint16(0) == 0x5a4d and
      filesize < 1000KB and all of them
}