rule blackhole_basic_ren: exploit_kit {
  strings:
    $a = /\.php\?.*:[a-zA-Z0-9\:]{6,}&.*&/

  condition:
    $a
}