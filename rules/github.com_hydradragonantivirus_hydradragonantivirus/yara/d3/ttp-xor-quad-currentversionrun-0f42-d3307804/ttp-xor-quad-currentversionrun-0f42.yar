rule TTP_XOR_QUAD_CurrentVersionRun_0f42 {
  strings:
    $key_0f42 = { 5c 2d [2] 78 23 [2] 53 0f [2] 7d 2d [2] 69 36 [2] 66 2c [2] 78 31 [2] 7a 30 [2] 61 36 [2] 7d 31 [2] 61 1e }

  condition:
    any of them
}