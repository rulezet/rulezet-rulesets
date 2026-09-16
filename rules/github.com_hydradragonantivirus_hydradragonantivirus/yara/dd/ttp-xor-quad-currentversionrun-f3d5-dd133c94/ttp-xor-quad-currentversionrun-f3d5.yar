rule TTP_XOR_QUAD_CurrentVersionRun_f3d5 {
  strings:
    $key_f3d5 = { a0 ba [2] 84 b4 [2] af 98 [2] 81 ba [2] 95 a1 [2] 9a bb [2] 84 a6 [2] 86 a7 [2] 9d a1 [2] 81 a6 [2] 9d 89 }

  condition:
    any of them
}