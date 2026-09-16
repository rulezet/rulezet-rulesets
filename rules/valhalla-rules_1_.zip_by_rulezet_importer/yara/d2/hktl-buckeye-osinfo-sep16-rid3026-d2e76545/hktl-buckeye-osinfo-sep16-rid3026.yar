rule HKTL_Buckeye_Osinfo_Sep16_RID3026 : DEMO EXE FILE G0022 HKTL {
   meta:
      description = "Detects OSinfo tool used by the Buckeye APT group"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://www.symantec.com/connect/blogs/buckeye-cyberespionage-group-shifts-gaze-us-hong-kong"
      date = "2016-09-05 12:27:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      id = "e40a86d1-fd1a-5430-b7b7-8cc7ca128cc5"
      tags = "DEMO, EXE, FILE, G0022, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "-s ShareInfo ShareDir" fullword ascii
      $s2 = "-a Local And Global Group User Info" fullword ascii
      $s3 = "-f <infile> //input server list from infile, OneServerOneLine" fullword ascii
      $s4 = "info <\\server> <user>" fullword ascii
      $s5 = "-c Connect Test" fullword ascii
      $s6 = "-gd Group Domain Admins" fullword ascii
      $s7 = "-n NetuseInfo" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and 3 of ( $s* )
}