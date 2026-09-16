rule TTP_XOR_QUAD_CurrentVersionRun_772c {
  strings:
    $key_772c = { 24 43 [2] 00 4d [2] 2b 61 [2] 05 43 [2] 11 58 [2] 1e 42 [2] 00 5f [2] 02 5e [2] 19 58 [2] 05 5f [2] 19 70 }

  condition:
    any of them
}