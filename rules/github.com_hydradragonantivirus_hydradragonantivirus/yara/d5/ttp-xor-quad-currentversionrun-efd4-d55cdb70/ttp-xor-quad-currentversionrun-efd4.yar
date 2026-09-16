rule TTP_XOR_QUAD_CurrentVersionRun_efd4 {
  strings:
    $key_efd4 = { bc bb [2] 98 b5 [2] b3 99 [2] 9d bb [2] 89 a0 [2] 86 ba [2] 98 a7 [2] 9a a6 [2] 81 a0 [2] 9d a7 [2] 81 88 }

  condition:
    any of them
}