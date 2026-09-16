import "pe"
rule MAL_XMR_Miner_May19_1_RID2E1B : DEMO EXE FILE HIGHVOL MAL {
   meta:
      description = "Detects Monero Crypto Coin Miner"
      author = "Florian Roth"
      reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
      date = "2019-05-31 11:00:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d6df423efb576f167bc28b3c08d10c397007ba323a0de92d1e504a3f490752fc"
      tags = "DEMO, EXE, FILE, HIGHVOL, MAL"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "donate.ssl.xmrig.com" fullword ascii
      $x2 = "* COMMANDS     'h' hashrate, 'p' pause, 'r' resume" fullword ascii
      $s1 = "[%s] login error code: %d" fullword ascii
      $s2 = "\\\\?\\pipe\\uv\\%p-%lu" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 14000KB and ( pe.imphash ( ) == "25d9618d1e16608cd5d14d8ad6e1f98e" or 1 of ( $x* ) or 2 of them )
}