rule infected_09_30_18_wp_load {
  meta:
    description = "shell2 - file wp-load.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-30"
    hash1       = "4095f37c624a3d93600dd974343fa016c4b16090c07cf39c523382ec34956dc9"

  strings:
    $s1  = "if (fopen(\"$subdira/.$algo\", 'w')) { $ura = 1; $eb = \"$subdira/\"; $hdl = fopen(\"$subdira/.$algo\", 'w'); break; }" fullword ascii
    $s2  = "$data = file_get_contents($url);" fullword ascii
    $s3  = "if (fopen(\"$dira/.$algo\", 'w')) { $ura = 1; $eb = \"$dira/\"; $hdl = fopen(\"$dira/.$algo\", 'w'); break; }" fullword ascii
    $s4  = "if (!$ura && fopen(\".$algo\", 'w')) { $ura = 1; $eb = ''; $hdl = fopen(\".$algo\", 'w'); }" fullword ascii
    $s5  = "$pass = \"Zgc5c4MXrLUscwQO6MwbPPGCf1TVMvlanyHMAanN\";" fullword ascii
    $s6  = "$reqw = $ay($ao($oa(\"$pass\"), 'wp_function'));" fullword ascii
    $s7  = "curl_setopt($ch, CURLOPT_HEADER, 0);" fullword ascii
    $s8  = "function get_data_ya($url) {" fullword ascii
    $s9  = "$ea = '_shaesx_'; $ay = 'get_data_ya'; $ae = 'decode'; $ea = str_replace('_sha', 'bas', $ea); $ao = 'wp_cd'; $ee = $ea.$ae; $oa " ascii
    $s10 = "@ini_set('display_errors', '0');" fullword ascii
    $s11 = "$ea = '_shaesx_'; $ay = 'get_data_ya'; $ae = 'decode'; $ea = str_replace('_sha', 'bas', $ea); $ao = 'wp_cd'; $ee = $ea.$ae; $oa " ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 10KB and
      (8 of them)
    ) or (all of them)
}