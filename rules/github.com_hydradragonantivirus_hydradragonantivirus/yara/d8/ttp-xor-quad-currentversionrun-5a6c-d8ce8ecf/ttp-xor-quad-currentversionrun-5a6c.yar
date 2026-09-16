rule TTP_XOR_QUAD_CurrentVersionRun_5a6c {
  strings:
    $key_5a6c = { 09 03 [2] 2d 0d [2] 06 21 [2] 28 03 [2] 3c 18 [2] 33 02 [2] 2d 1f [2] 2f 1e [2] 34 18 [2] 28 1f [2] 34 30 }

  condition:
    any of them
}