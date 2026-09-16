rule TTP_XOR_QUAD_CurrentVersionRun_2c22 {
  strings:
    $key_2c22 = { 7f 4d [2] 5b 43 [2] 70 6f [2] 5e 4d [2] 4a 56 [2] 45 4c [2] 5b 51 [2] 59 50 [2] 42 56 [2] 5e 51 [2] 42 7e }

  condition:
    any of them
}