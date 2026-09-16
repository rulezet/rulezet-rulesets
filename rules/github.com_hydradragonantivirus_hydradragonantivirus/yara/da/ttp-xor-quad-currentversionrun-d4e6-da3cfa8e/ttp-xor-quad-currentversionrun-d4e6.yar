rule TTP_XOR_QUAD_CurrentVersionRun_d4e6 {
  strings:
    $key_d4e6 = { 87 89 [2] a3 87 [2] 88 ab [2] a6 89 [2] b2 92 [2] bd 88 [2] a3 95 [2] a1 94 [2] ba 92 [2] a6 95 [2] ba ba }

  condition:
    any of them
}