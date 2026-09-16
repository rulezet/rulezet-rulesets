rule TTP_XOR_QUAD_CurrentVersionRun_d4f6 {
  strings:
    $key_d4f6 = { 87 99 [2] a3 97 [2] 88 bb [2] a6 99 [2] b2 82 [2] bd 98 [2] a3 85 [2] a1 84 [2] ba 82 [2] a6 85 [2] ba aa }

  condition:
    any of them
}