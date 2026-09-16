rule CN_Honker_portRecall_pr_RID3020 : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file pr"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:26:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Usage: Same as lcx.exe in win32 :)" fullword ascii
      $s2 = "connect to client" fullword ascii
      $s3 = "PR(Packet redirection) for linux " fullword ascii
   condition: 
      filesize < 70KB and all of them
}