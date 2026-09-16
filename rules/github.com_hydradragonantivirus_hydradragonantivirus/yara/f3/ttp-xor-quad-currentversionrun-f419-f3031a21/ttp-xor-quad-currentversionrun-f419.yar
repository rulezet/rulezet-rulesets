rule TTP_XOR_QUAD_CurrentVersionRun_f419 {
  strings:
    $key_f419 = { a7 76 [2] 83 78 [2] a8 54 [2] 86 76 [2] 92 6d [2] 9d 77 [2] 83 6a [2] 81 6b [2] 9a 6d [2] 86 6a [2] 9a 45 }

  condition:
    any of them
}