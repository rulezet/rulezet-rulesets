rule TTP_XOR_QUAD_CurrentVersionRun_e344 {
  strings:
    $key_e344 = { b0 2b [2] 94 25 [2] bf 09 [2] 91 2b [2] 85 30 [2] 8a 2a [2] 94 37 [2] 96 36 [2] 8d 30 [2] 91 37 [2] 8d 18 }

  condition:
    any of them
}