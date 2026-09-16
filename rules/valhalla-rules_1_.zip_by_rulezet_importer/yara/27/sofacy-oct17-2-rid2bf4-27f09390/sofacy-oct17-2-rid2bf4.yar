import "pe"
rule Sofacy_Oct17_2_RID2BF4 : APT DEMO EXE FILE G0007 RUSSIA {
   meta:
      description = "Detects Sofacy malware reported in October 2017"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2017/10/cyber-conflict-decoy-document.html"
      date = "2017-10-23 09:28:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ef027405492bc0719437eb58c3d2774cc87845f30c40040bbebbcc09a4e3dd18"
      tags = "APT, DEMO, EXE, FILE, G0007, RUSSIA"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "netwf.dll" fullword wide
      $s1 = "%s - %s - %2.2x" fullword wide
      $s2 = "%s - %lu" fullword ascii
      $s3 = "%s \"%s\", %s" fullword wide
      $s4 = "%j%Xjsf" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 90KB and ( pe.imphash ( ) == "13344e2a717849489bcd93692f9646f7" or ( 4 of them ) ) ) or ( all of them )
}