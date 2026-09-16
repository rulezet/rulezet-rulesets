rule Msfpayloads_msf_6_RID2DCE : APT DEMO METASPLOIT SCRIPT {
   meta:
      description = "Metasploit Payloads - file msf.vbs"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09 10:47:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8d6f55c6715c4a2023087c3d0d7abfa21e31a629393e4dc179d31bb25b166b3f"
      tags = "APT, DEMO, METASPLOIT, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii
      $s2 = "= CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s3 = ".GetSpecialFolder(2)" ascii
      $s4 = ".Write Chr(CLng(\"" ascii
      $s5 = "= \"4d5a90000300000004000000ffff00" ascii
      $s6 = "For i = 1 to Len(" ascii
      $s7 = ") Step 2" ascii
   condition: 
      5 of them
}