rule TTP_XOR_QUAD_CurrentVersionRun_476c {
  strings:
    $key_476c = { 14 03 [2] 30 0d [2] 1b 21 [2] 35 03 [2] 21 18 [2] 2e 02 [2] 30 1f [2] 32 1e [2] 29 18 [2] 35 1f [2] 29 30 }

  condition:
    any of them
}