rule Msfpayloads_msf_2_RID2DCA : APT DEMO METASPLOIT {
   meta:
      description = "Metasploit Payloads - file msf.asp"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09 10:46:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e52f98466b92ee9629d564453af6f27bd3645e00a9e2da518f5a64a33ccf8eb5"
      tags = "APT, DEMO, METASPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "& \"\\\" & \"svchost.exe\"" fullword ascii
      $s2 = "CreateObject(\"Wscript.Shell\")" fullword ascii
      $s3 = "<% @language=\"VBScript\" %>" fullword ascii
   condition: 
      all of them
}