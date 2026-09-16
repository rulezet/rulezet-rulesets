rule SUSP_RTF_Header_Anomaly_RID2F7F : ANOMALY DEMO FILE SUSP {
   meta:
      description = "Detects malformed RTF header often used to trick mechanisms that check for a full RTF header"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/975705759618158593"
      date = "2019-01-20 11:59:41"
      score = 55
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-09-15"
      tags = "ANOMALY, DEMO, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   condition: 
      uint32 ( 0 ) == 0x74725c7b and not uint8 ( 4 ) == 0x66
}