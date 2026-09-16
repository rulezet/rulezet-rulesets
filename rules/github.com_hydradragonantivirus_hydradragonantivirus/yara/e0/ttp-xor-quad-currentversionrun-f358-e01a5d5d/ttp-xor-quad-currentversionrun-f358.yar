rule TTP_XOR_QUAD_CurrentVersionRun_f358 {
  strings:
    $key_f358 = { a0 37 [2] 84 39 [2] af 15 [2] 81 37 [2] 95 2c [2] 9a 36 [2] 84 2b [2] 86 2a [2] 9d 2c [2] 81 2b [2] 9d 04 }

  condition:
    any of them
}