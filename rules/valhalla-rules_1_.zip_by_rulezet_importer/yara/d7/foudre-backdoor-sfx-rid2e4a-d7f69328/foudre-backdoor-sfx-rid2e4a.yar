rule Foudre_Backdoor_SFX_RID2E4A : DEMO EXE FILE MAL {
   meta:
      description = "Detects Foudre Backdoor SFX"
      author = "Florian Roth"
      reference = "https://www.paloaltonetworks.com/blog/2017/08/unit42-prince-persia-ride-lightning-infy-returns-foudre/"
      date = "2017-08-01 11:08:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "2b37ce9e31625d8b9e51b88418d4bf38ed28c77d98ca59a09daab01be36d405a"
      hash2 = "4d51a0ea4ecc62456295873ff135e4d94d5899c4de749621bafcedbf4417c472"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "main.exe" fullword ascii
      $s2 = "pub.key" fullword ascii
      $s3 = "WinRAR self-extracting archive" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}