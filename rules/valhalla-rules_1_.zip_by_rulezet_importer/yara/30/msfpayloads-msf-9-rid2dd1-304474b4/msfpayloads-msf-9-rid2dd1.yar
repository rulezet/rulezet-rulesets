rule Msfpayloads_msf_9_RID2DD1 : APT DEMO FILE METASPLOIT {
   meta:
      description = "Metasploit Payloads - file msf.war - contents"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09 10:48:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e408678042642a5d341e8042f476ee7cef253871ef1c9e289acf0ee9591d1e81"
      tags = "APT, DEMO, FILE, METASPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if (System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") != -1)" fullword ascii
      $s2 = ".concat(\".exe\");" fullword ascii
      $s3 = "[0] = \"chmod\";" ascii
      $s4 = "= Runtime.getRuntime().exec(" ascii
      $s5 = ", 16) & 0xff;" ascii
      $x1 = "4d5a9000030000000" ascii
   condition: 
      4 of ( $s* ) or ( uint32 ( 0 ) == 0x61356434 and $x1 at 0 )
}