rule HKTL_shellpop_socat_RID2E83 : DEMO HKTL {
   meta:
      description = "Detects suspicious socat popshell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18 11:17:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "267f69858a5490efb236628260b275ad4bbfeebf4a83fab8776e333ca706a6a0"
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "socat tcp-connect" ascii
      $s2 = ",pty,stderr,setsid,sigint,sane" ascii
   condition: 
      filesize < 1KB and 2 of them
}