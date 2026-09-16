rule CN_APT_ZeroT_nflogger_RID2EEC : APT CHINA DEMO EXE FILE {
   meta:
      description = "Chinese APT by Proofpoint ZeroT RAT  - file nflogger.dll"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
      date = "2017-02-04 11:35:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "946adbeb017616d56193a6d43fe9c583be6ad1c7f6a22bab7df9db42e6e8ab10"
      tags = "APT, CHINA, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\LoaderDll.VS2010\\Release\\" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}