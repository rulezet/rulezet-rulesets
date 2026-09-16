rule Msfpayloads_msf_5_RID2DCD : APT DEMO METASPLOIT {
   meta:
      description = "Metasploit Payloads - file msf.msi"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09 10:47:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7a6c66dfc998bf5838993e40026e1f400acd018bde8d4c01ef2e2e8fba507065"
      tags = "APT, DEMO, METASPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "required to install Foobar 1.0." fullword ascii
      $s2 = "Copyright 2009 The Apache Software Foundation." fullword wide
      $s3 = "{50F36D89-59A8-4A40-9689-8792029113AC}" fullword ascii
   condition: 
      all of them
}