rule TTP_XOR_QUAD_CurrentVersionRun_dec1 {
  strings:
    $key_dec1 = { 8d ae [2] a9 a0 [2] 82 8c [2] ac ae [2] b8 b5 [2] b7 af [2] a9 b2 [2] ab b3 [2] b0 b5 [2] ac b2 [2] b0 9d }

  condition:
    any of them
}