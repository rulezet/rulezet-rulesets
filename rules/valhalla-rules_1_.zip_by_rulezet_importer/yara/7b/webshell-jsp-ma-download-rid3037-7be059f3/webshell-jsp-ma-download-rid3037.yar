rule Webshell_JSP_MA_download_RID3037 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 201.jsp, 3.jsp, ma.jsp, download.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:30:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fb8c6c3a69b93e5e7193036fd31a958d"
      hash2 = "4cc68fa572e88b669bce606c7ace0ae9"
      hash3 = "fa87bbd7201021c1aefee6fcc5b8e25a"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<input title=\"Upload selected file to the current working directory\" type=\"Su" 
      $s5 = "<input title=\"Launch command in current directory\" type=\"Submit\" class=\"but" 
      $s6 = "<input title=\"Delete all selected files and directories incl. subdirs\" class=" 
   condition: 
      all of them
}