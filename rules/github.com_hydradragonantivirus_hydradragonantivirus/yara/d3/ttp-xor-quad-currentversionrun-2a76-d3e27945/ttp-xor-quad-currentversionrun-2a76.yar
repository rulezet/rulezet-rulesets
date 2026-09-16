rule TTP_XOR_QUAD_CurrentVersionRun_2a76 {
  strings:
    $key_2a76 = { 79 19 [2] 5d 17 [2] 76 3b [2] 58 19 [2] 4c 02 [2] 43 18 [2] 5d 05 [2] 5f 04 [2] 44 02 [2] 58 05 [2] 44 2a }

  condition:
    any of them
}