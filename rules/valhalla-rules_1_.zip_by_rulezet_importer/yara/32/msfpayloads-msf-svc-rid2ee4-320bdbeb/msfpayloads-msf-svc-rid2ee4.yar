rule Msfpayloads_msf_svc_RID2EE4 : APT DEMO EXE FILE METASPLOIT {
   meta:
      description = "Metasploit Payloads - file msf-svc.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09 11:33:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2b02c9c10577ee0c7590d3dadc525c494122747a628a7bf714879b8e94ae5ea1"
      tags = "APT, DEMO, EXE, FILE, METASPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "PAYLOAD:" fullword ascii
      $s2 = ".exehll" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 50KB and all of them )
}