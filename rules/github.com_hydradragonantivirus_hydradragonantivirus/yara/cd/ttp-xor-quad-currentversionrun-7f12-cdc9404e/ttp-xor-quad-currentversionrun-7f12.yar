rule TTP_XOR_QUAD_CurrentVersionRun_7f12 {
  strings:
    $key_7f12 = { 2c 7d [2] 08 73 [2] 23 5f [2] 0d 7d [2] 19 66 [2] 16 7c [2] 08 61 [2] 0a 60 [2] 11 66 [2] 0d 61 [2] 11 4e }

  condition:
    any of them
}