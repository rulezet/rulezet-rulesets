rule SUSP_PDB_CN_Threat_Actor_May19_1_RID3220 : CHINA DEMO EXE FILE SUSP {
   meta:
      description = "Detects PDB path user name used by Chinese threat actors"
      author = "Florian Roth"
      reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
      date = "2019-05-31 13:51:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "01c3882e8141a25abe37bb826ab115c52fd3d109c4a1b898c0c78cee8dac94b4"
      tags = "CHINA, DEMO, EXE, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "C:\\Users\\zcg\\Desktop\\" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and 1 of them
}