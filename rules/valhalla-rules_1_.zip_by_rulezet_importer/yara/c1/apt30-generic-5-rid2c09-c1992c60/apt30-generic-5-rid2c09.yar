rule APT30_Generic_5_RID2C09 : APT DEMO FILE G0013 GEN T1218_010 {
   meta:
      description = "FireEye APT30 Report Sample - from files 592381dfa14e61bce089cd00c9b118ae, b493ad490b691b8732983dcca8ea8b6f, b83d43e3b2f0b0a0e5cc047ef258c2cb"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:32:01"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dfc9a87df2d585c479ab02602133934b055d156f"
      hash2 = "bf59d5ff7d38ec5ffb91296e002e8742baf24db5"
      tags = "APT, DEMO, FILE, G0013, GEN, T1218_010"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "regsvr32 /s \"%ProgramFiles%\\Norton360\\Engine\\5.1.0.29\\ashelper.dll\"" fullword
      $s1 = "name=\"ftpserver.exe\"/>" fullword
      $s2 = "LiveUpdate.EXE" fullword wide
      $s3 = "<description>FTP Explorer</description>" fullword
      $s4 = "\\ashelper.dll" 
      $s5 = "LiveUpdate" fullword wide
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}