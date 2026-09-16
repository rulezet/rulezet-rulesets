rule CN_Honker_linux_bin_RID2E8F : CHINA DEMO LINUX SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file linux_bin"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:19:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, LINUX, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "client.sin_port = htons(atoi(argv[3]));" fullword ascii
      $s2 = "printf(\"\\n\\n*********Waiting Client connect*****\\n\\n\");" fullword ascii
   condition: 
      filesize < 20KB and all of them
}