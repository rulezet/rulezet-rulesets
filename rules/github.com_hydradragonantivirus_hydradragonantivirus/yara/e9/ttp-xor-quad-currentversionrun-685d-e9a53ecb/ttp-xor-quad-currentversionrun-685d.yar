rule TTP_XOR_QUAD_CurrentVersionRun_685d {
  strings:
    $key_685d = { 3b 32 [2] 1f 3c [2] 34 10 [2] 1a 32 [2] 0e 29 [2] 01 33 [2] 1f 2e [2] 1d 2f [2] 06 29 [2] 1a 2e [2] 06 01 }

  condition:
    any of them
}