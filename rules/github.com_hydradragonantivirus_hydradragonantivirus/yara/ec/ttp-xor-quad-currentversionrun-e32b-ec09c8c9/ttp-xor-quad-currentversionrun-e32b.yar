rule TTP_XOR_QUAD_CurrentVersionRun_e32b {
  strings:
    $key_e32b = { b0 44 [2] 94 4a [2] bf 66 [2] 91 44 [2] 85 5f [2] 8a 45 [2] 94 58 [2] 96 59 [2] 8d 5f [2] 91 58 [2] 8d 77 }

  condition:
    any of them
}