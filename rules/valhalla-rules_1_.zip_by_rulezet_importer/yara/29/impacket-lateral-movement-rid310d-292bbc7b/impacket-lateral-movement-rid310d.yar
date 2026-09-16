rule Impacket_Lateral_Movement_RID310D : DEMO EXE FILE HKTL {
   meta:
      description = "Detects Impacket Network Aktivity for Lateral Movement"
      author = "Markus Neis"
      reference = "https://github.com/CoreSecurity/impacket"
      date = "2018-03-22 13:06:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "impacket.dcerpc.v5.transport(" ascii
      $s2 = "impacket.smbconnection(" ascii
      $s3 = "impacket.dcerpc.v5.ndr(" ascii
      $s4 = "impacket.spnego(" ascii
      $s5 = "impacket.smb(" ascii
      $s6 = "impacket.ntlm(" ascii
      $s7 = "impacket.nmb(" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 14000KB and 2 of them
}