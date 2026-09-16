rule TTP_XOR_QUAD_CurrentVersionRun_32c8 {
  strings:
    $key_32c8 = { 61 a7 [2] 45 a9 [2] 6e 85 [2] 40 a7 [2] 54 bc [2] 5b a6 [2] 45 bb [2] 47 ba [2] 5c bc [2] 40 bb [2] 5c 94 }

  condition:
    any of them
}