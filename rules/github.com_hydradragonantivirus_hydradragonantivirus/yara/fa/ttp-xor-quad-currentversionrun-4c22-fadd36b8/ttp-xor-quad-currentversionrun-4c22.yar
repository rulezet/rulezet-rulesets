rule TTP_XOR_QUAD_CurrentVersionRun_4c22 {
  strings:
    $key_4c22 = { 1f 4d [2] 3b 43 [2] 10 6f [2] 3e 4d [2] 2a 56 [2] 25 4c [2] 3b 51 [2] 39 50 [2] 22 56 [2] 3e 51 [2] 22 7e }

  condition:
    any of them
}