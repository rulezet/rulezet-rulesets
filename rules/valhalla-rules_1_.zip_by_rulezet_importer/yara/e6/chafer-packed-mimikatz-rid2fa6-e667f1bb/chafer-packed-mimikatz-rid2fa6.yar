rule Chafer_Packed_Mimikatz_RID2FA6 : APT DEMO EXE FILE G0049 G0087 MIDDLE_EAST S0002 T1003 T1027_002 T1134_005 T1550_002 T1550_003 {
   meta:
      description = "Detects Oilrig Packed Mimikatz also detected as Chafer_WSC_x64 by FR"
      author = "Florian Roth, Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22 12:06:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5f2c3b5a08bda50cca6385ba7d84875973843885efebaff6a482a38b3cb23a7c"
      tags = "APT, DEMO, EXE, FILE, G0049, G0087, MIDDLE_EAST, S0002, T1003, T1027_002, T1134_005, T1550_002, T1550_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Windows Security Credentials" fullword wide
      $s2 = "Minisoft" fullword wide
      $x1 = "Copyright (c) 2014 - 2015 Minisoft" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and ( all of ( $s* ) or $x1 )
}