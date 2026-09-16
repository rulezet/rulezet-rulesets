rule TTP_XOR_QUAD_CurrentVersionRun_e3d4 {
  strings:
    $key_e3d4 = { b0 bb [2] 94 b5 [2] bf 99 [2] 91 bb [2] 85 a0 [2] 8a ba [2] 94 a7 [2] 96 a6 [2] 8d a0 [2] 91 a7 [2] 8d 88 }

  condition:
    any of them
}