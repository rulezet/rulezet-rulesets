rule EXPL_Strings_CVE_POC_May19_1_RID3091 : DEMO EXE EXPLOIT FILE {
   meta:
      description = "Detects strings used in CVE POC noticed in May 2019"
      author = "Florian Roth"
      reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
      date = "2019-05-31 12:45:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "01c3882e8141a25abe37bb826ab115c52fd3d109c4a1b898c0c78cee8dac94b4"
      tags = "DEMO, EXE, EXPLOIT, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\Debug\\poc_cve_20" ascii
      $x2 = "\\Release\\poc_cve_20" ascii
      $x3 = "alloc fake fail: %x!" fullword ascii
      $x4 = "Allocate fake tagWnd fail!" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and 1 of them
}