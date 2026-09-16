rule TTP_XOR_QUAD_CurrentVersionRun_ded9 {
  strings:
    $key_ded9 = { 8d b6 [2] a9 b8 [2] 82 94 [2] ac b6 [2] b8 ad [2] b7 b7 [2] a9 aa [2] ab ab [2] b0 ad [2] ac aa [2] b0 85 }

  condition:
    any of them
}