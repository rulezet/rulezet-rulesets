rule CN_APT_ZeroT_extracted_Mcutil_RID3229 : APT CHINA DEMO EXE FILE {
   meta:
      description = "Chinese APT by Proofpoint ZeroT RAT  - file Mcutil.dll"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-04 13:53:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "266c06b06abbed846ebabfc0e683f5d20dadab52241bc166b9d60e9b8493b500"
      tags = "APT, CHINA, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "LoaderDll.dll" fullword ascii
      $s2 = "QageBox1USER" fullword ascii
      $s3 = "xhmowl" fullword ascii
      $s4 = "?KEYKY" fullword ascii
      $s5 = "HH:mm:_s" fullword ascii
      $s6 = "=licni] has maX0t" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 90KB and 3 of them ) or ( all of them )
}