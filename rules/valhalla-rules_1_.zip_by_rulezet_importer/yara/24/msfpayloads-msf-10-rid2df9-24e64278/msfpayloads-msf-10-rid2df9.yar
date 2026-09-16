rule Msfpayloads_msf_10_RID2DF9 : APT DEMO EXE FILE METASPLOIT {
   meta:
      description = "Metasploit Payloads - file msf.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09 10:54:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3cd74fa28323c0d64f45507675ac08fb09bae4dd6b7e11f2832a4fbc70bb7082"
      tags = "APT, DEMO, EXE, FILE, METASPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = { 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 } 
      $s2 = { 01 c7 38 e0 75 f6 03 7d f8 3b 7d 24 75 e4 58 8b } 
      $s3 = { 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}