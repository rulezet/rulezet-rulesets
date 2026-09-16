rule SUSP_XMRIG_Reference {
   meta:
      description = "Detects an executable with a suspicious XMRIG crypto miner reference"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/itaitevet/status/1141677424045953024"
      date = "2019-06-20"
      score = 70
      id = "0a7324ce-90dc-5e6a-b22a-c29eccf324e9"
   strings:
      $x1 = "\\xmrig\\" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}