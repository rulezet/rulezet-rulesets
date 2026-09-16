rule TTP_XOR_QUAD_CurrentVersionRun_336c {
  strings:
    $key_336c = { 60 03 [2] 44 0d [2] 6f 21 [2] 41 03 [2] 55 18 [2] 5a 02 [2] 44 1f [2] 46 1e [2] 5d 18 [2] 41 1f [2] 5d 30 }

  condition:
    any of them
}