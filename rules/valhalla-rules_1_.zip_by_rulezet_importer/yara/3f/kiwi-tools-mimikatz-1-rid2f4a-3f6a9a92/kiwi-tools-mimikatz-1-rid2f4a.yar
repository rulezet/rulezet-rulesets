rule Kiwi_Tools_Mimikatz_1_RID2F4A : CHINA DEMO EXE FILE HKTL S0002 T1003 T1134_005 T1550_002 T1550_003 {
   meta:
      description = "Chinese Hacktool Set - from mimikatz files"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 11:50:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
      hash2 = "7ac7541e20af7755b7d8141c5c1b7432465cabd8"
      hash3 = "9fbfe3eb49d67347ab57ae743f7542864bc06de6"
      tags = "CHINA, DEMO, EXE, FILE, HKTL, S0002, T1003, T1134_005, T1550_002, T1550_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "http://blog.gentilkiwi.com/mimikatz" ascii
      $s2 = "Benjamin Delpy" fullword ascii
      $s3 = "GlobalSign" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them
}