rule TTP_XOR_QUAD_CurrentVersionRun_2842 {
  strings:
    $key_2842 = { 7b 2d [2] 5f 23 [2] 74 0f [2] 5a 2d [2] 4e 36 [2] 41 2c [2] 5f 31 [2] 5d 30 [2] 46 36 [2] 5a 31 [2] 46 1e }

  condition:
    any of them
}