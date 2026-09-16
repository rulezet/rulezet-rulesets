rule Webshell_acid_FaTaLisTiCz_Fx_fx_p0isoN_sh3ll_x0rg_byp4ss_256_RID3D6B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell - rule generated from from files acid.php, FaTaLisTiCz_Fx.txt, fx.txt, p0isoN.sh3ll.txt, x0rg.byp4ss.txt"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 21:53:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
      hash2 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
      hash3 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<form method=\"POST\"><input type=hidden name=act value=\"ls\">" fullword ascii
      $s2 = "foreach($quicklaunch2 as $item) {" fullword ascii
   condition: 
      filesize < 882KB and all of them
}