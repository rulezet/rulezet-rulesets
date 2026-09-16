rule TTP_XOR_QUAD_CurrentVersionRun_6322 {
  strings:
    $key_6322 = { 30 4d [2] 14 43 [2] 3f 6f [2] 11 4d [2] 05 56 [2] 0a 4c [2] 14 51 [2] 16 50 [2] 0d 56 [2] 11 51 [2] 0d 7e }

  condition:
    any of them
}