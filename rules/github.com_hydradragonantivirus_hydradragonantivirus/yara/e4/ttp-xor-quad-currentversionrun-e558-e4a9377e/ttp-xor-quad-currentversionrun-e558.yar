rule TTP_XOR_QUAD_CurrentVersionRun_e558 {
  strings:
    $key_e558 = { b6 37 [2] 92 39 [2] b9 15 [2] 97 37 [2] 83 2c [2] 8c 36 [2] 92 2b [2] 90 2a [2] 8b 2c [2] 97 2b [2] 8b 04 }

  condition:
    any of them
}