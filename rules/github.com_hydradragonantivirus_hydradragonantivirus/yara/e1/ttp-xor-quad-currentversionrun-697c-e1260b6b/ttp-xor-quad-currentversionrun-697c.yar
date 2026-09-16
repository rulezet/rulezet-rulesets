rule TTP_XOR_QUAD_CurrentVersionRun_697c {
  strings:
    $key_697c = { 3a 13 [2] 1e 1d [2] 35 31 [2] 1b 13 [2] 0f 08 [2] 00 12 [2] 1e 0f [2] 1c 0e [2] 07 08 [2] 1b 0f [2] 07 20 }

  condition:
    any of them
}