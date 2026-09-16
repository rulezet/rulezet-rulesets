rule TTP_XOR_QUAD_CurrentVersionRun_654b {
  strings:
    $key_654b = { 36 24 [2] 12 2a [2] 39 06 [2] 17 24 [2] 03 3f [2] 0c 25 [2] 12 38 [2] 10 39 [2] 0b 3f [2] 17 38 [2] 0b 17 }

  condition:
    any of them
}