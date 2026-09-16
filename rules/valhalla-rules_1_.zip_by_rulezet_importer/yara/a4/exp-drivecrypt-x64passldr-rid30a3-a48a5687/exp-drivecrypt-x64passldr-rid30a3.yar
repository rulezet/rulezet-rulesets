rule EXP_DriveCrypt_x64passldr_RID30A3 : DEMO EXE EXPLOIT FILE {
   meta:
      description = "Detects DriveCrypt exploit"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-08-21 12:48:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      hash1 = "c828304c83619e2cb9dab80305e5286aba91742dc550e1469d91812af27101a1"
      tags = "DEMO, EXE, EXPLOIT, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\x64\\x64passldr.pdb" ascii
      $s2 = "\\amd64\\x64pass.sys" wide
      $s3 = "\\\\.\\DCR" fullword ascii
      $s4 = "Open SC Mgr Error" fullword ascii
      $s5 = "thing is ok " fullword ascii
      $s6 = "x64pass" fullword wide
      $s7 = "%ws\\%ws\\Security" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 3 of them
}