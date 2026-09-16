rule CN_Honker__builder_shift_SkinH_RID32C6 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - from files builder.exe, shift.exe, SkinH.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:19:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ee127c1ea1e3b5bf3d2f8754fabf9d1101ed0ee0"
      hash2 = "d593f03ae06e54b653c7850c872c0eed459b301f"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "lipboard" fullword ascii
      $s2 = "uxthem" fullword ascii
      $s3 = "ENIGMA" fullword ascii
      $s4 = "UtilW0ndow" fullword ascii
      $s5 = "prog3am" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 6075KB and all of them
}