rule Quasar_RAT_2_RID2B55 : DEMO EXE FILE MAL QuasarRAT {
   meta:
      description = "Detects Quasar RAT"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07 09:02:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0774d25e33ca2b1e2ee2fafe3fdbebecefbf1d4dd99e6460f0bc8713dd0fd740"
      hash2 = "515c1a68995557035af11d818192f7866ef6a2018aa13112fefbe08395732e89"
      hash3 = "f08db220df716de3d4f63f3007a03f902601b9b32099d6a882da87312f263f34"
      tags = "DEMO, EXE, FILE, MAL, QuasarRAT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "GetKeyloggerLogsResponse" fullword ascii
      $x2 = "get_Keylogger" fullword ascii
      $x3 = "HandleGetKeyloggerLogsResponse" fullword ascii
      $s1 = "DoShellExecuteResponse" fullword ascii
      $s2 = "GetPasswordsResponse" fullword ascii
      $s3 = "GetStartupItemsResponse" fullword ascii
      $s4 = "<GetGenReader>b__7" fullword ascii
      $s5 = "RunHidden" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 5000KB and $x1 ) or ( all of them )
}