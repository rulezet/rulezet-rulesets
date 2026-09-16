rule SUSP_ZIP_NtdsDIT_RID2C87 : DEMO FILE SUSP T1003_003 T1020 {
   meta:
      description = "Detects ntds.dit files in ZIP archives that could be a left over of administrative activity or traces of data exfiltration"
      author = "Florian Roth"
      reference = "https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/"
      date = "2020-08-10 09:53:01"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, SUSP, T1003_003, T1020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ntds.dit" ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and $s1 in ( 0 .. 256 )
}