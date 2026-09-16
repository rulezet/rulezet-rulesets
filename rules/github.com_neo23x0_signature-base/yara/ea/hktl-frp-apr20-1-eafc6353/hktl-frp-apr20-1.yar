rule HKTL_FRP_Apr20_1 {
   meta:
      description = "Detects FRP fast reverse proxy tool often used by threat groups"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/fatedier/frp"
      date = "2020-04-07"
      modified = "2022-11-03"
      score = 70
      hash1 = "05537c1c4e29db76a24320fb7cb80b189860389cdb16a9dbeb0c8d30d9b37006"
      hash2 = "08c685c8febb5385f7548c2a64a27bae7123a937c5af958ebc08a3accb29978d"
      id = "55483832-0e0b-5c28-8be5-dbd14ddb50e3"
   strings:
      $x1 = "frp/vendor/github.com/spf13/" ascii
      $x2 = "github.com/fatedier/frp/vendor/" ascii

      $fpg2 = "<html"
      $fpg3 = "<HTML"
      $fpg6 = "<?xml"
   condition:
      1 of ($x*) and not 1 of ($fp*)
}