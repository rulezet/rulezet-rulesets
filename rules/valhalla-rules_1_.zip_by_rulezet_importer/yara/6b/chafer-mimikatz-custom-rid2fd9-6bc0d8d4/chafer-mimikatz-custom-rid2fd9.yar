rule Chafer_Mimikatz_Custom_RID2FD9 : APT DEMO EXE FILE G0087 MIDDLE_EAST S0002 T1003 T1134_005 T1550_002 T1550_003 {
   meta:
      description = "Detects Custom Mimikatz Version"
      author = "Florian Roth, Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22 12:14:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9709afeb76532566ee3029ecffc76df970a60813bcac863080cc952ad512b023"
      tags = "APT, DEMO, EXE, FILE, G0087, MIDDLE_EAST, S0002, T1003, T1134_005, T1550_002, T1550_003"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "C:\\Users\\win7p\\Documents\\mi-back\\" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and 1 of them
}