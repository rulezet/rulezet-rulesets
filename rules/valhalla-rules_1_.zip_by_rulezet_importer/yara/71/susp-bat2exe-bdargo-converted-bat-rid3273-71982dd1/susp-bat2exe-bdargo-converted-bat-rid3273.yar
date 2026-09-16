rule SUSP_BAT2EXE_BDargo_Converted_BAT_RID3273 : DEMO EXE FILE SCRIPT SUSP {
   meta:
      description = "Detects binaries created with BDARGO Advanced BAT to EXE converter"
      author = "Florian Roth"
      reference = "https://www.majorgeeks.com/files/details/advanced_bat_to_exe_converter.html"
      date = "2018-07-28 14:05:41"
      score = 45
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-06-23"
      hash1 = "d428d79f58425d831c2ee0a73f04749715e8c4dd30ccd81d92fe17485e6dfcda"
      hash2 = "a547a02eb4fcb8f446da9b50838503de0d46f9bb2fd197c9ff63021243ea6d88"
      tags = "DEMO, EXE, FILE, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Error #bdembed1 -- Quiting" fullword ascii
      $s2 = "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s" fullword ascii
      $s3 = "\\a.txt" ascii
      $s4 = "command.com" fullword ascii
      $s6 = "DFDHERGDCV" fullword ascii
      $s7 = "DFDHERGGZV" fullword ascii
      $s8 = "%s%s%s%s%s%s%s%s" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 5 of them
}