rule HKTL_shellpop_Netcat_UDP_RID3010 : DEMO HKTL {
   meta:
      description = "Detects suspicious netcat popshell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18 12:23:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d823ad91b315c25893ce8627af285bcf4e161f9bbf7c070ee2565545084e88be"
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "mkfifo fifo ; nc.traditional -u" ascii
      $s2 = "< fifo | { bash -i; } > fifo" fullword ascii
   condition: 
      filesize < 1KB and 1 of them
}