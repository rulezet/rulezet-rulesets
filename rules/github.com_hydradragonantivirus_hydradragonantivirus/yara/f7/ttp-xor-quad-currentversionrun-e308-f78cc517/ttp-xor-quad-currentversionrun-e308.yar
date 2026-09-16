rule TTP_XOR_QUAD_CurrentVersionRun_e308 {
  strings:
    $key_e308 = { b0 67 [2] 94 69 [2] bf 45 [2] 91 67 [2] 85 7c [2] 8a 66 [2] 94 7b [2] 96 7a [2] 8d 7c [2] 91 7b [2] 8d 54 }

  condition:
    any of them
}