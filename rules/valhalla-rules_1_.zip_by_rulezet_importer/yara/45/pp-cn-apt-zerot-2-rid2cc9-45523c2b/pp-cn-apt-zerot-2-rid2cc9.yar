rule PP_CN_APT_ZeroT_2_RID2CC9 : APT CHINA DEMO EXE FILE {
   meta:
      description = "Detects malware from the Proofpoint CN APT ZeroT incident"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-03 10:04:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "74eb592ef7f5967b14794acdc916686e061a43169f06e5be4dca70811b9815df"
      tags = "APT, CHINA, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "NO2-2016101902.exe" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}