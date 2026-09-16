rule dat_NaslLib_RID2B4E : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file NaslLib.dll"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:00:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "nessus_get_socket_from_connection: fd <%d> is closed" fullword ascii
      $s2 = "[*] \"%s\" completed, %d/%d/%d/%d:%d:%d - %d/%d/%d/%d:%d:%d" fullword ascii
      $s3 = "A FsSniffer backdoor seems to be running on this port%s" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1360KB and all of them
}