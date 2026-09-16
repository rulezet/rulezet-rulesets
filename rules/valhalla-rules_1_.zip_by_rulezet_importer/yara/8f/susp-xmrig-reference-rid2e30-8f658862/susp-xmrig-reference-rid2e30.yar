rule SUSP_XMRIG_Reference_RID2E30 : DEMO EXE FILE SUSP xmrig {
   meta:
      description = "Detects an executable with a suspicious XMRIG crypto miner reference"
      author = "Florian Roth"
      reference = "https://twitter.com/itaitevet/status/1141677424045953024"
      date = "2019-06-20 11:03:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, SUSP, xmrig"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\xmrig\\" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them
}