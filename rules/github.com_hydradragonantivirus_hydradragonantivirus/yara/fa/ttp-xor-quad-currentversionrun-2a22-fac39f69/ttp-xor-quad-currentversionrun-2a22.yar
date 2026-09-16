rule TTP_XOR_QUAD_CurrentVersionRun_2a22 {
  strings:
    $key_2a22 = { 79 4d [2] 5d 43 [2] 76 6f [2] 58 4d [2] 4c 56 [2] 43 4c [2] 5d 51 [2] 5f 50 [2] 44 56 [2] 58 51 [2] 44 7e }

  condition:
    any of them
}