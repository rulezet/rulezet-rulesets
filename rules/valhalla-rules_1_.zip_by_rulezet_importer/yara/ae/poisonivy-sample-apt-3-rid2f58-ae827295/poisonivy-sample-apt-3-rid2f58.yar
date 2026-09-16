rule PoisonIvy_Sample_APT_3_RID2F58 : APT DEMO EXE FILE {
   meta:
      description = "Detects a PoisonIvy Malware"
      author = "Florian Roth"
      reference = "VT Analysis"
      date = "2015-06-03 11:53:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\notepad.exe" ascii
      $s1 = "\\RasAuto.dll" ascii
      $s3 = "winlogon.exe" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and all of them
}