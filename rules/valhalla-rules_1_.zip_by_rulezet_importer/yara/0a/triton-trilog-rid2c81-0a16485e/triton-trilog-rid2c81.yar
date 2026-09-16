rule Triton_trilog_RID2C81 : APT DEMO EXE FILE {
   meta:
      description = "Detects Triton APT malware - file trilog.exe"
      author = "Florian Roth"
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/attackers-deploy-new-ics-attack-framework-triton/"
      date = "2017-12-14 09:52:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "e8542c07b2af63ee7e72ce5d97d91036c5da56e2b091aa2afe737b224305d230"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "inject.bin" ascii
      $s2 = "PYTHON27.DLL" fullword ascii
      $s3 = "payload" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 60KB and all of them
}