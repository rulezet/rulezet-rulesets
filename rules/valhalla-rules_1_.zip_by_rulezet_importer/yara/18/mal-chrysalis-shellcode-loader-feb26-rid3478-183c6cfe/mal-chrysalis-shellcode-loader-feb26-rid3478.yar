rule MAL_Chrysalis_Shellcode_Loader_Feb26_RID3478 : CHINA Chrysalis DEMO G0030 MAL {
   meta:
      description = "Detects shellcode used to load Chrysalis backdoor, seen being used in the compromise of the infrastructure hosting Notepad++ by Chinese APT group Lotus Blossom"
      author = "X__Junior"
      reference = "https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/"
      date = "2026-02-02 15:31:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, Chrysalis, DEMO, G0030, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 8B C7 03 D7 83 E0 ?? 47 8A 4C 05 ?? 8A 04 13 02 C1 32 C1 2A C1 88 02 8B 55 ?? 3B FE 7C ?? 8B 5D ?? 8B 45 } 
      $op2 = { 03 F8 8B 45 ?? 8B 50 ?? 85 C9 79 ?? 0F B7 C1 EB ?? 8D 41 ?? 03 C3 50 FF 75 ?? FF D2 89 07 85 C0 74 ?? 8B 4D ?? 46 } 
   condition: 
      1 of them
}