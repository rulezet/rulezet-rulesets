rule Winnti_signing_cert_RID2EE5 : CHINA DEMO EXE FILE G0044 MAL {
   meta:
      description = "Detects a signing certificate used by the Winnti APT group"
      author = "Florian Roth"
      reference = "https://securelist.com/analysis/publications/72275/i-am-hdroot-part-1/"
      date = "2015-10-10 11:34:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a9a8dc4ae77b1282f0c8bdebd2643458fc1ceb3145db4e30120dd81676ff9b61"
      hash2 = "9001572983d5b1f99787291edaadbb65eb2701722f52470e89db2c59def24672"
      tags = "CHINA, DEMO, EXE, FILE, G0044, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Guangzhou YuanLuo Technology Co." ascii
      $s2 = "Guangzhou YuanLuo Technology Co.,Ltd" ascii
      $s3 = "$Asahi Kasei Microdevices Corporation0" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 700KB and 1 of them
}