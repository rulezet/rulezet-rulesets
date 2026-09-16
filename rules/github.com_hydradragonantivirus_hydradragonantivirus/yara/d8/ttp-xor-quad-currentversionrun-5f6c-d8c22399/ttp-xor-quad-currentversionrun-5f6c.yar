rule TTP_XOR_QUAD_CurrentVersionRun_5f6c {
  strings:
    $key_5f6c = { 0c 03 [2] 28 0d [2] 03 21 [2] 2d 03 [2] 39 18 [2] 36 02 [2] 28 1f [2] 2a 1e [2] 31 18 [2] 2d 1f [2] 31 30 }

  condition:
    any of them
}