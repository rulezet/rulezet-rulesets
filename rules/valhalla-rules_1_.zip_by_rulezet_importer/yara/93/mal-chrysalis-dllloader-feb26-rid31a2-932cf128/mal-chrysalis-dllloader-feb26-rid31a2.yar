rule MAL_Chrysalis_DllLoader_Feb26_RID31A2 : CHINA Chrysalis DEMO EXE FILE G0030 MAL {
   meta:
      description = "Detects DLL used to load Chrysalis backdoor, seen being used in the compromise of the infrastructure hosting Notepad++ by Chinese APT group Lotus Blossom"
      author = "X__Junior"
      reference = "https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/"
      date = "2026-02-02 13:30:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, Chrysalis, DEMO, EXE, FILE, G0030, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 33 D2 8B C1 F7 F6 0F B6 C1 03 55 ?? 6B C0 ?? 32 02 88 04 0F 41 83 F9 ?? 72 } 
      $op2 = { 0F B6 04 31 41 33 C2 69 D0 ?? ?? ?? ?? 3B CB 72 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and all of them
}