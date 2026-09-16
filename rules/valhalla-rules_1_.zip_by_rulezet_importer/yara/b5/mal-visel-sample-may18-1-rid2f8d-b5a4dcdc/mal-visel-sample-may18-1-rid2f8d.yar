import "pe"
rule MAL_Visel_Sample_May18_1_RID2F8D : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects Visel malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 12:02:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "35db8e6a2eb5cf09cd98bf5d31f6356d0deaf4951b353fc513ce98918b91439c"
      tags = "APT, DEMO, EXE, FILE, MAL"
      required_modules = "pe"
      minimum_yara = "3.6.0"
      
   strings:
      $s2 = "print32.dll" fullword ascii
      $s3 = "c:\\a\\b.txt" fullword ascii
      $s4 = "\\temp\\s%d.dat" wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and ( pe.exports ( "szFile" ) or 2 of them )
}