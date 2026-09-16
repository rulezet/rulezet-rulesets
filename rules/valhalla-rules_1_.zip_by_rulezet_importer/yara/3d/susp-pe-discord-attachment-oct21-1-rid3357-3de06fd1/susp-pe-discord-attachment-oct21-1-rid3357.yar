rule SUSP_PE_Discord_Attachment_Oct21_1_RID3357 : DEMO EXE FILE SUSP {
   meta:
      description = "Detects suspicious executable with reference to a Discord attachment (often used for malware hosting on a legitimate FQDN)"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2021-10-12 14:43:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "https://cdn.discordapp.com/attachments/" ascii wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 5000KB and 1 of them
}