rule TTP_XOR_QUAD_CurrentVersionRun_f7c8 {
  strings:
    $key_f7c8 = { a4 a7 [2] 80 a9 [2] ab 85 [2] 85 a7 [2] 91 bc [2] 9e a6 [2] 80 bb [2] 82 ba [2] 99 bc [2] 85 bb [2] 99 94 }

  condition:
    any of them
}