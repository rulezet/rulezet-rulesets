rule MAL_UNC2891_Caketap {
   meta:
      description = "Detects UNC2891 Rootkit Caketap"
      author = "Frank Boldewin (@r3c0nst)"
      date = "2022-03-30"
      reference = "https://github.com/fboldewin/YARA-rules/tree/master"

      id = "9c2ffe3d-69ca-5f93-bdb1-40e449139dec"
   strings:
      $str1  = ".caahGss187" ascii fullword       $str2 = "ipstat" ascii       $code1 = {41 80 7E 06 4B 75 ?? 41 80 7E 07 57 75 ?? 41 0F B6 46 2B}       $code2 = {41 C6 46 01 3D 41 C6 46 08 32}    condition:
      uint32 (0) ==  0x464c457f and (all of ($code*) or (all of ($str*) and #str2 == 2))
}