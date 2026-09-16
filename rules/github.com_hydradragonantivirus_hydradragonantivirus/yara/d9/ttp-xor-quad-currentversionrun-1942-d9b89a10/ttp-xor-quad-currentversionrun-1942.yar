rule TTP_XOR_QUAD_CurrentVersionRun_1942 {
  strings:
    $key_1942 = { 4a 2d [2] 6e 23 [2] 45 0f [2] 6b 2d [2] 7f 36 [2] 70 2c [2] 6e 31 [2] 6c 30 [2] 77 36 [2] 6b 31 [2] 77 1e }

  condition:
    any of them
}