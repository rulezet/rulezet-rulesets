rule Msfpayloads_msf_7_RID2DCF : APT DEMO METASPLOIT SCRIPT {
   meta:
      description = "Metasploit Payloads - file msf.vba"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09 10:47:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "425beff61a01e2f60773be3fcb74bdfc7c66099fe40b9209745029b3c19b5f2f"
      tags = "APT, DEMO, METASPLOIT, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Private Declare PtrSafe Function CreateThread Lib \"kernel32\" (ByVal" ascii
      $s2 = "= VirtualAlloc(0, UBound(Tsw), &H1000, &H40)" fullword ascii
      $s3 = "= RtlMoveMemory(" ascii
   condition: 
      all of them
}