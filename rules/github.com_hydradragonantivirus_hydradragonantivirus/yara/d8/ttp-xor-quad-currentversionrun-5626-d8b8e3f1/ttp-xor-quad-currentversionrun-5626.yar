rule TTP_XOR_QUAD_CurrentVersionRun_5626 {
  strings:
    $key_5626 = { 05 49 [2] 21 47 [2] 0a 6b [2] 24 49 [2] 30 52 [2] 3f 48 [2] 21 55 [2] 23 54 [2] 38 52 [2] 24 55 [2] 38 7a }

  condition:
    any of them
}