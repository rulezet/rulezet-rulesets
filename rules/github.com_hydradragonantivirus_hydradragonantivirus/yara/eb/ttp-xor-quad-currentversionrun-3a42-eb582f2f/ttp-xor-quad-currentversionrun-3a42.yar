rule TTP_XOR_QUAD_CurrentVersionRun_3a42 {
  strings:
    $key_3a42 = { 69 2d [2] 4d 23 [2] 66 0f [2] 48 2d [2] 5c 36 [2] 53 2c [2] 4d 31 [2] 4f 30 [2] 54 36 [2] 48 31 [2] 54 1e }

  condition:
    any of them
}