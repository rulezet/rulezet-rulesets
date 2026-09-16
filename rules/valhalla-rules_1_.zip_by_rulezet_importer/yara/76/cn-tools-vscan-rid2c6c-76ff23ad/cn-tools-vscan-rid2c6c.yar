rule CN_Tools_Vscan_RID2C6C : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file Vscan.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:48:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[+] Usage: VNC_bypauth <target> <scantype> <option>" fullword ascii
      $s2 = "========RealVNC <= 4.1.1 Bypass Authentication Scanner=======" fullword ascii
      $s3 = "[+] Type VNC_bypauth <target>,<scantype> or <option> for more informations" fullword ascii
      $s4 = "VNC_bypauth -i 192.168.0.1,192.168.0.2,192.168.0.3,..." fullword ascii
      $s5 = "-vn:%-15s:%-7d  connection closed" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 60KB and 2 of them
}