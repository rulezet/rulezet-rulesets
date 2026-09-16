rule MAL_SeaDuke_Sample_RID2DAD : DEMO EXE FILE MAL {
   meta:
      description = "SeaDuke Malware"
      author = "Florian Roth"
      reference = "https://www.paloaltonetworks.com/blog/2015/07/unit-42-technical-analysis-seaduke/"
      date = "2015-07-14 10:42:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "bpython27.dll" fullword ascii
      $s1 = "email.header(" ascii
      $s2 = "LogonUI.exe" fullword wide
      $s3 = "Crypto.Cipher.AES(" ascii
      $s4 = "mod is NULL - %s" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 4000KB and all of them
}