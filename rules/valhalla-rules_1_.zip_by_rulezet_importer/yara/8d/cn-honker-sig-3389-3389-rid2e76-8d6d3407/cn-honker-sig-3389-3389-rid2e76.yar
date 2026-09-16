rule CN_Honker_sig_3389_3389_RID2E76 : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file 3389.vbs"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:15:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "success = obj.run(\"cmd /c takeown /f %SystemRoot%\\system32\\sethc.exe&echo y| " ascii
   condition: 
      filesize < 10KB and all of them
}