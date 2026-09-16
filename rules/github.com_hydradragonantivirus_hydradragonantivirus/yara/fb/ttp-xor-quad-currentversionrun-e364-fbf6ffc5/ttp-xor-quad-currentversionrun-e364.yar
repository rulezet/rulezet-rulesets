rule TTP_XOR_QUAD_CurrentVersionRun_e364 {
  strings:
    $key_e364 = { b0 0b [2] 94 05 [2] bf 29 [2] 91 0b [2] 85 10 [2] 8a 0a [2] 94 17 [2] 96 16 [2] 8d 10 [2] 91 17 [2] 8d 38 }

  condition:
    any of them
}