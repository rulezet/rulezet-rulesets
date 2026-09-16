rule Webshell_c100_RID2B9A : DEMO T1087_001 T1105 T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell - rule generated from from files c100 v. 777shell"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 09:13:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
      hash2 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
      hash3 = "21dd06ec423f0b49732e4289222864dcc055967922d0fcec901d38a57ed77f06"
      tags = "DEMO, T1087_001, T1105, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/debug/k3\">Kernel attack (Krad.c) PT1 (If wget installed)" fullword ascii
      $s1 = "<center>Kernel Info: <form name=\"form1\" method=\"post\" action=\"http://google.com/search\">" fullword ascii
      $s3 = "cut -d: -f1,2,3 /etc/passwd | grep ::" ascii
      $s4 = "which wget curl w3m lynx" ascii
      $s6 = "netstat -atup | grep IST" ascii
   condition: 
      filesize < 685KB and 2 of them
}