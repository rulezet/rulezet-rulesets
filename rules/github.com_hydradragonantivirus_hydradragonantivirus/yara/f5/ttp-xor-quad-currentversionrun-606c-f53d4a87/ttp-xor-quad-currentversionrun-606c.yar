rule TTP_XOR_QUAD_CurrentVersionRun_606c {
  strings:
    $key_606c = { 33 03 [2] 17 0d [2] 3c 21 [2] 12 03 [2] 06 18 [2] 09 02 [2] 17 1f [2] 15 1e [2] 0e 18 [2] 12 1f [2] 0e 30 }

  condition:
    any of them
}