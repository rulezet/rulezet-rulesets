rule APT_CN_MAL_RedDelta_Shellcode_Loader_Oct20_3_RID36A4 : APT CHINA DEMO EXE FILE G0129 MAL {
   meta:
      description = "Detects Red Delta samples"
      author = "Florian Roth"
      reference = "https://twitter.com/JAMESWT_MHT/status/1316387482708119556"
      date = "2020-10-14 17:04:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      hash1 = "740992d40b84b10aa9640214a4a490e989ea7b869cea27dbbdef544bb33b1048"
      tags = "APT, CHINA, DEMO, EXE, FILE, G0129, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Taskschd.dll" ascii fullword
      $s2 = "AddTaskPlanDllVerson.dll" ascii fullword
      $s3 = "\\FlashUpdate.exe" ascii
      $s4 = "D:\\Project\\FBIRedTeam" ascii fullword
      $s5 = "Error %s:%d, ErrorCode: %x" ascii fullword
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and 4 of them
}