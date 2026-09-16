rule TTP_XOR_QUAD_CurrentVersionRun_c5d9 {
  strings:
    $key_c5d9 = { 96 b6 [2] b2 b8 [2] 99 94 [2] b7 b6 [2] a3 ad [2] ac b7 [2] b2 aa [2] b0 ab [2] ab ad [2] b7 aa [2] ab 85 }

  condition:
    any of them
}