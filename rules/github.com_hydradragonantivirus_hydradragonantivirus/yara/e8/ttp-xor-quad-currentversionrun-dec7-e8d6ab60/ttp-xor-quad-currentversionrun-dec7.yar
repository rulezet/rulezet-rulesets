rule TTP_XOR_QUAD_CurrentVersionRun_dec7 {
  strings:
    $key_dec7 = { 8d a8 [2] a9 a6 [2] 82 8a [2] ac a8 [2] b8 b3 [2] b7 a9 [2] a9 b4 [2] ab b5 [2] b0 b3 [2] ac b4 [2] b0 9b }

  condition:
    any of them
}