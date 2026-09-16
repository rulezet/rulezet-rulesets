rule TTP_XOR_QUAD_CurrentVersionRun_61c8 {
  strings:
    $key_61c8 = { 32 a7 [2] 16 a9 [2] 3d 85 [2] 13 a7 [2] 07 bc [2] 08 a6 [2] 16 bb [2] 14 ba [2] 0f bc [2] 13 bb [2] 0f 94 }

  condition:
    any of them
}