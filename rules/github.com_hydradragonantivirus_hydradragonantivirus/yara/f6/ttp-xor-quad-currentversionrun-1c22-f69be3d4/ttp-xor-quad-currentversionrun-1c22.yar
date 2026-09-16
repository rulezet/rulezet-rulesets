rule TTP_XOR_QUAD_CurrentVersionRun_1c22 {
  strings:
    $key_1c22 = { 4f 4d [2] 6b 43 [2] 40 6f [2] 6e 4d [2] 7a 56 [2] 75 4c [2] 6b 51 [2] 69 50 [2] 72 56 [2] 6e 51 [2] 72 7e }

  condition:
    any of them
}