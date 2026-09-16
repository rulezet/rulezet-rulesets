rule FreeMilk_APT_Mal_3_RID2D6F : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware from FreeMilk campaign"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/"
      date = "2017-10-05 10:31:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ef40f7ddff404d1193e025081780e32f88883fa4dd496f4189084d772a435cb2"
      tags = "APT, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "CMD.EXE /C \"%s\"" fullword wide
      $s2 = "\\command\\start.exe" wide
      $s3 = ".bat;.com;.cmd;.exe" fullword wide
      $s4 = "Unexpected failure opening HKCR key: %d" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 900KB and all of them )
}