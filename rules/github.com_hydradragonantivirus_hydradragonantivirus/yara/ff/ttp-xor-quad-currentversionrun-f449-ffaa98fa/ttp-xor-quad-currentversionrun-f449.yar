rule TTP_XOR_QUAD_CurrentVersionRun_f449 {
  strings:
    $key_f449 = { a7 26 [2] 83 28 [2] a8 04 [2] 86 26 [2] 92 3d [2] 9d 27 [2] 83 3a [2] 81 3b [2] 9a 3d [2] 86 3a [2] 9a 15 }

  condition:
    any of them
}