rule TTP_XOR_QUAD_CurrentVersionRun_4d33 {
  strings:
    $key_4d33 = { 1e 5c [2] 3a 52 [2] 11 7e [2] 3f 5c [2] 2b 47 [2] 24 5d [2] 3a 40 [2] 38 41 [2] 23 47 [2] 3f 40 [2] 23 6f }

  condition:
    any of them
}