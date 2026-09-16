rule TTP_XOR_QUAD_CurrentVersionRun_11c8 {
  strings:
    $key_11c8 = { 42 a7 [2] 66 a9 [2] 4d 85 [2] 63 a7 [2] 77 bc [2] 78 a6 [2] 66 bb [2] 64 ba [2] 7f bc [2] 63 bb [2] 7f 94 }

  condition:
    any of them
}