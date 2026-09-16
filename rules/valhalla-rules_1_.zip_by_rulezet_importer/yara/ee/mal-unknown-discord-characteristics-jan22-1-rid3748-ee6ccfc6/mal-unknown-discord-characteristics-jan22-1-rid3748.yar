rule MAL_Unknown_Discord_Characteristics_Jan22_1_RID3748 : DEMO EXE FILE MAL {
   meta:
      description = "Detects unknown malware with a few indicators also found in Wiper malware"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/"
      date = "2022-01-16 17:31:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "xownxloxadDxatxxax" wide
      $s2 = "https://cdn.discordapp.com/attachments/" wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them
}