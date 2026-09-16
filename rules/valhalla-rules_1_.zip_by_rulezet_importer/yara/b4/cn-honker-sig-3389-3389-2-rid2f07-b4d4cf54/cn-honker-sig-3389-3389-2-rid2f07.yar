rule CN_Honker_sig_3389_3389_2_RID2F07 : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file 3389.bat"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:39:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "@del c:\\termsrvhack.dll" fullword ascii
      $s2 = "@del c:\\3389.txt" fullword ascii
   condition: 
      filesize < 3KB and all of them
}