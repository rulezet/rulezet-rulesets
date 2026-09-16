rule SUSP_WER_Critical_HeapCorruption_Oct19_RID3534 : DEMO FILE SUSP {
   meta:
      description = "Detects a crashed application that crashed due to a heap corruption error (could be a sign of exploitation)"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1185459425710092288"
      date = "2019-10-18 16:03:11"
      score = 40
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-11-22"
      tags = "DEMO, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "ReportIdentifier=" wide
      $a2 = ".Name=Fault Module Name" wide
      $s1 = "c0000374" wide
   condition: 
      ( uint32be ( 0 ) == 0x56006500 or uint32be ( 0 ) == 0xfffe5600 ) and all of them
}