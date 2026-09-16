rule TTP_XOR_QUAD_CurrentVersionRun_4d26 {
  strings:
    $key_4d26 = { 1e 49 [2] 3a 47 [2] 11 6b [2] 3f 49 [2] 2b 52 [2] 24 48 [2] 3a 55 [2] 38 54 [2] 23 52 [2] 3f 55 [2] 23 7a }

  condition:
    any of them
}