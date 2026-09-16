rule SUSP_ZIP_NtdsDIT : T1003_003 {
   meta:
      description = "Detects ntds.dit files in ZIP archives that could be a left over of administrative activity or traces of data exfiltration"
      author = "Florian Roth (Nextron Systems)"
      score = 50
      reference = "https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/"
      date = "2020-08-10"
      id = "131ed73d-bb34-5ff6-b145-f95e4469d7f9"
   strings:
      $s1 = "ntds.dit" ascii 
   condition:
      uint16(0) == 0x4b50 and
      $s1 in (0..256)
}