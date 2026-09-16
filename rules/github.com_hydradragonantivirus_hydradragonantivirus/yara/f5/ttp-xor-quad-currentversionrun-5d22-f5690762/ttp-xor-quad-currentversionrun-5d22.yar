rule TTP_XOR_QUAD_CurrentVersionRun_5d22 {
  strings:
    $key_5d22 = { 0e 4d [2] 2a 43 [2] 01 6f [2] 2f 4d [2] 3b 56 [2] 34 4c [2] 2a 51 [2] 28 50 [2] 33 56 [2] 2f 51 [2] 33 7e }

  condition:
    any of them
}