rule PP_CN_APT_ZeroT_8_RID2CCF : APT CHINA DEMO FILE T1218_001 {
   meta:
      description = "Detects malware from the Proofpoint CN APT ZeroT incident"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-03 10:05:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4ef91c17b1415609a2394d2c6c353318a2503900e400aab25ab96c9fe7dc92ff"
      tags = "APT, CHINA, DEMO, FILE, T1218_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "/svchost.exe" fullword ascii
      $s2 = "RasTls.dll" fullword ascii
      $s3 = "20160620.htm" fullword ascii
      $s4 = "/20160620.htm" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5449 and filesize < 1000KB and 3 of them )
}