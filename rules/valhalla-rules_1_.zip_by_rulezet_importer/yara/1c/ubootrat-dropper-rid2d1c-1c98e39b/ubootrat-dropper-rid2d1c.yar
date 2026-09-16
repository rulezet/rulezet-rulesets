rule UBootRAT_Dropper_RID2D1C : APT DEMO EXE FILE {
   meta:
      description = "Detects UBootRAT Dropper"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/"
      date = "2017-11-29 10:17:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f4c659238ffab95e87894d2c556f887774dce2431e8cb87f881df4e4d26253a3"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "GetCurrenvackageId" fullword ascii
      $s2 = "fghijklmnopq" fullword ascii
      $s3 = "23456789:;<=>?@ABCDEFGHIJKLMNOPQ" fullword ascii
      $s4 = "PMM/dd/y" fullword ascii
      $s5 = "bad all" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}