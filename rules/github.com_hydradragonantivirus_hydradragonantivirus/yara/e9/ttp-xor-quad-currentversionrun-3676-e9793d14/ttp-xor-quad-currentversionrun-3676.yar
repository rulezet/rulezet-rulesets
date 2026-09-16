rule TTP_XOR_QUAD_CurrentVersionRun_3676 {
  strings:
    $key_3676 = { 65 19 [2] 41 17 [2] 6a 3b [2] 44 19 [2] 50 02 [2] 5f 18 [2] 41 05 [2] 43 04 [2] 58 02 [2] 44 05 [2] 58 2a }

  condition:
    any of them
}