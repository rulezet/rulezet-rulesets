rule PP_CN_APT_ZeroT_1_RID2CC8 : APT CHINA DEMO EXE FILE {
   meta:
      description = "Detects malware from the Proofpoint CN APT ZeroT incident"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-03 10:03:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "09061c603a32ac99b664f7434febfc8c1f9fd7b6469be289bb130a635a6c47c0"
      tags = "APT, CHINA, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "suprise.exe" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}