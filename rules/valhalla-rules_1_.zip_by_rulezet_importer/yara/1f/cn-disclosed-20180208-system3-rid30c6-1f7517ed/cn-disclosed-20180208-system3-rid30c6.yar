rule CN_disclosed_20180208_System3_RID30C6 : CHINA DEMO EXE FILE MAL {
   meta:
      description = "Detects malware from disclosed CN malware set"
      author = "Florian Roth"
      reference = "https://twitter.com/cyberintproject/status/961714165550342146"
      date = "2018-02-08 12:54:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "73fa84cff51d384c2d22d9e53fc5d42cb642172447b07e796c81dd403fb010c2"
      tags = "CHINA, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "WmiPrvSE.exe" fullword wide
      $s1 = "C:\\Users\\sgl\\AppData\\Local\\" ascii
      $s2 = "Temporary Projects\\WmiPrvSE\\" ascii
      $s3 = "$15a32a5d-4906-458a-8f57-402311afc1c1" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and $a1 and 1 of ( $s* )
}