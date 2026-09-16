rule TTP_XOR_QUAD_CurrentVersionRun_4d6c {
  strings:
    $key_4d6c = { 1e 03 [2] 3a 0d [2] 11 21 [2] 3f 03 [2] 2b 18 [2] 24 02 [2] 3a 1f [2] 38 1e [2] 23 18 [2] 3f 1f [2] 23 30 }

  condition:
    any of them
}