rule TTP_XOR_QUAD_CurrentVersionRun_1b6c {
  strings:
    $key_1b6c = { 48 03 [2] 6c 0d [2] 47 21 [2] 69 03 [2] 7d 18 [2] 72 02 [2] 6c 1f [2] 6e 1e [2] 75 18 [2] 69 1f [2] 75 30 }

  condition:
    any of them
}