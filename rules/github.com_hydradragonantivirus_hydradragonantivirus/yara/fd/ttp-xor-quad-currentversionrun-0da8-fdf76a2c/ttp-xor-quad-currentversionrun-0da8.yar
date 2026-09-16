rule TTP_XOR_QUAD_CurrentVersionRun_0da8 {
  strings:
    $key_0da8 = { 5e c7 [2] 7a c9 [2] 51 e5 [2] 7f c7 [2] 6b dc [2] 64 c6 [2] 7a db [2] 78 da [2] 63 dc [2] 7f db [2] 63 f4 }

  condition:
    any of them
}