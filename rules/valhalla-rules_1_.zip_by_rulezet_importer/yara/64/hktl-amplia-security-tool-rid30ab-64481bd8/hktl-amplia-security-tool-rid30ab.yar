rule HKTL_Amplia_Security_Tool_RID30AB : DEMO EXE HKTL SUSP T1003 {
   meta:
      description = "Detects Amplia Security Tool like Windows Credential Editor"
      author = "Florian Roth"
      reference = "-"
      date = "2013-01-01 12:49:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-02-14"
      tags = "DEMO, EXE, HKTL, SUSP, T1003"
      minimum_yara = "3.5.0"
      
   strings:
      $a = "Amplia Security" 
      $c = "getlsasrvaddr.exe" 
      $d = "Cannot get PID of LSASS.EXE" 
      $e = "extract the TGT session key" 
      $f = "PPWDUMP_DATA" 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and ( 2 of them ) or 3 of them
}