rule TTP_XOR_QUAD_CurrentVersionRun_2173 {
  strings:
    $key_2173 = { 72 1c [2] 56 12 [2] 7d 3e [2] 53 1c [2] 47 07 [2] 48 1d [2] 56 00 [2] 54 01 [2] 4f 07 [2] 53 00 [2] 4f 2f }

  condition:
    any of them
}