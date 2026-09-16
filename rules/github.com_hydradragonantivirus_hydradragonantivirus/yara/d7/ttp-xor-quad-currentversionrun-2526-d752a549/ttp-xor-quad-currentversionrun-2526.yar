rule TTP_XOR_QUAD_CurrentVersionRun_2526 {
  strings:
    $key_2526 = { 76 49 [2] 52 47 [2] 79 6b [2] 57 49 [2] 43 52 [2] 4c 48 [2] 52 55 [2] 50 54 [2] 4b 52 [2] 57 55 [2] 4b 7a }

  condition:
    any of them
}