rule TTP_XOR_QUAD_CurrentVersionRun_7e42 {
  strings:
    $key_7e42 = { 2d 2d [2] 09 23 [2] 22 0f [2] 0c 2d [2] 18 36 [2] 17 2c [2] 09 31 [2] 0b 30 [2] 10 36 [2] 0c 31 [2] 10 1e }

  condition:
    any of them
}