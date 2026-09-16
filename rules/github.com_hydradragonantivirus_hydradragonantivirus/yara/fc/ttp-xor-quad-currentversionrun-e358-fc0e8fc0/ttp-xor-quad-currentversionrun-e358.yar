rule TTP_XOR_QUAD_CurrentVersionRun_e358 {
  strings:
    $key_e358 = { b0 37 [2] 94 39 [2] bf 15 [2] 91 37 [2] 85 2c [2] 8a 36 [2] 94 2b [2] 96 2a [2] 8d 2c [2] 91 2b [2] 8d 04 }

  condition:
    any of them
}