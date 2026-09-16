rule backdoor_wp_config {
  meta:
    description = "work1 - file backdoor_wp-config.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-12-22"
    hash1       = "5057d290bbf35f7440ce7fa9c30354c8442fa77080f41066530c76d06b242008"

  strings:
    $s1  = "= str_replace('sx', '64', $ee); $algo = 'kolotyska'; $pass = \"Zgc5c4MXrL8kbQBSs88NKfKeflvUNPlfnyDNGK/X/wEfeQ==\";" fullword ascii
    $s2  = "if (fopen(\"$subdira/.$algo\", 'w')) { $ura = 1; $eb = \"$subdira/\"; $hdl = fopen(\"$subdira/.$algo\", 'w'); break; }" fullword ascii
    $s3  = "$data = file_get_contents($url);" fullword ascii
    $s4  = "if (fopen(\"$dira/.$algo\", 'w')) { $ura = 1; $eb = \"$dira/\"; $hdl = fopen(\"$dira/.$algo\", 'w'); break; }" fullword ascii
    $s5  = "if (!$ura && fopen(\".$algo\", 'w')) { $ura = 1; $eb = ''; $hdl = fopen(\".$algo\", 'w'); }" fullword ascii
    $s6  = "define( 'DB_PASSWORD', '' );" fullword ascii
    $s7  = "define( 'SECURE_AUTH_KEY',  '' );" fullword ascii
    $s8  = "/* That's all, stop editing! Happy publishing. */" fullword ascii
    $s9  = "$ea = '_shaesx_'; $ay = 'get_data_ya'; $ae = 'decode'; $ea = str_replace('_sha', 'bas', $ea); $ao = 'wp_cd'; $ee = $ea.$ae; $oa " ascii
    $s10 = "$reqw = $ay($ao($oa(\"$pass\"), 'wp_function'));" fullword ascii
    $s11 = "curl_setopt($ch, CURLOPT_HEADER, 0);" fullword ascii
    $s12 = "require_once( ABSPATH . 'wp-settings.php' );" fullword ascii
    $s13 = "function get_data_ya($url) {" fullword ascii
    $s14 = "define( 'DB_HOST', 'localhost' );" fullword ascii
    $s15 = "$ea = '_shaesx_'; $ay = 'get_data_ya'; $ae = 'decode'; $ea = str_replace('_sha', 'bas', $ea); $ao = 'wp_cd'; $ee = $ea.$ae; $oa " ascii
    $s16 = "define( 'LOGGED_IN_KEY',    '' );" fullword ascii
    $s17 = "@ini_set('display_errors', '0');" fullword ascii
    $s18 = "define( 'SECURE_AUTH_SALT', '' );" fullword ascii

  condition:
    (uint16(0) == 0x3c0a and
      filesize < 10KB and
      (8 of them)
    ) or (all of them)
}