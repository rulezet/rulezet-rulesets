rule HKTL_shellpop_ruby_RID2E2B : DEMO HKTL {
   meta:
      description = "Detects suspicious ruby shellpop"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18 11:03:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6b425b37f3520fd8c778928cc160134a293db0ce6d691e56a27894354b04f783"
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = ");while(cmd=c.gets);IO.popen(cmd,'r'){" ascii
   condition: 
      filesize < 1KB and all of them
}