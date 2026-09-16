rule CN_Tools_xsniff_RID2CFF : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file xsniff.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:13:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "xsiff.exe -pass -hide -log pass.log" fullword ascii
      $s1 = "HOST: %s USER: %s, PASS: %s" fullword ascii
      $s2 = "xsiff.exe -tcp -udp -asc -addr 192.168.1.1" fullword ascii
      $s10 = "Code by glacier <glacier@xfocus.org>" fullword ascii
      $s11 = "%-5s%s->%s Bytes=%d TTL=%d Type: %d,%d ID=%d SEQ=%d" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 220KB and 2 of them
}