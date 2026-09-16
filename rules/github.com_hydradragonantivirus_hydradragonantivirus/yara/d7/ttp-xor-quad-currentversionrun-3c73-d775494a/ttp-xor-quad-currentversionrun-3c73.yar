rule TTP_XOR_QUAD_CurrentVersionRun_3c73 {
  strings:
    $key_3c73 = { 6f 1c [2] 4b 12 [2] 60 3e [2] 4e 1c [2] 5a 07 [2] 55 1d [2] 4b 00 [2] 49 01 [2] 52 07 [2] 4e 00 [2] 52 2f }

  condition:
    any of them
}