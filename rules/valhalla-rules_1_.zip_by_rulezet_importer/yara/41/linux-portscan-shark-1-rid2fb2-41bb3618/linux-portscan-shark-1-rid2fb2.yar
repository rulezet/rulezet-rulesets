rule Linux_Portscan_Shark_1_RID2FB2 : DEMO FILE HKTL LINUX T1046 {
   meta:
      description = "Detects Linux Port Scanner Shark"
      author = "Florian Roth"
      reference = "Virustotal Research - see https://github.com/Neo23x0/Loki/issues/35"
      date = "2016-04-01 12:08:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4da0e535c36c0c52eaa66a5df6e070c52e7ddba13816efc3da5691ea2ec06c18"
      hash2 = "e395ca5f932419a4e6c598cae46f17b56eb7541929cdfb67ef347d9ec814dea3"
      tags = "DEMO, FILE, HKTL, LINUX, T1046"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "rm -rf scan.log session.txt" fullword ascii
      $s17 = "*** buffer overflow detected ***: %s terminated" fullword ascii
      $s18 = "*** stack smashing detected ***: %s terminated" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7362 and all of them )
}