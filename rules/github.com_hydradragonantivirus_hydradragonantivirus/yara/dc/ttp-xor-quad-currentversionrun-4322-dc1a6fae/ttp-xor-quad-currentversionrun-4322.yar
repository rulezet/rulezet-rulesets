rule TTP_XOR_QUAD_CurrentVersionRun_4322 {
  strings:
    $key_4322 = { 10 4d [2] 34 43 [2] 1f 6f [2] 31 4d [2] 25 56 [2] 2a 4c [2] 34 51 [2] 36 50 [2] 2d 56 [2] 31 51 [2] 2d 7e }

  condition:
    any of them
}