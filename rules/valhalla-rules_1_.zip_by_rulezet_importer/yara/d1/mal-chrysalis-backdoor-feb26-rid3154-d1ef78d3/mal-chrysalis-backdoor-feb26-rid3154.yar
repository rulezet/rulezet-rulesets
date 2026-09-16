rule MAL_Chrysalis_Backdoor_Feb26_RID3154 : CHINA Chrysalis DEMO G0030 MAL {
   meta:
      description = "Detects Chrysalis backdoor, seen being used in the compromise of the infrastructure hosting Notepad++ by Chinese APT group Lotus Blossom"
      author = "X__Junior"
      reference = "https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/"
      date = "2026-02-02 13:17:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, Chrysalis, DEMO, G0030, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $opa1 = { 8B 4D ?? C1 CF ?? C1 C1 ?? 03 F9 D1 C3 8B 4D ?? C1 C1 ?? 03 F9 03 FB 8B 5D ?? 69 CF ?? ?? ?? ?? BF ?? ?? ?? ?? 2B F9 EB } 
      $opa2 = { F7 E9 [0-1] 8B C2 C1 E8 ?? 03 C2 8D 0C 40 8A C3 34 ?? [0-2] 0F B6 [1-4] 0F B6 C3 8B 5D [1-3] 0F 45 D0 } 
      $opb1 = { 0F B6 84 35 ?? ?? ?? ?? 88 84 3D ?? ?? ?? ?? 88 8C 35 ?? ?? ?? ?? 0F B6 84 3D ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 03 C2 0F B6 C0 0F B6 84 05 ?? ?? ?? ?? 30 04 19 43 3B 9D ?? ?? ?? ?? 7C } 
   condition: 
      ( 1 of ( $opa* ) and $opb1 ) or all of ( $opa* )
}