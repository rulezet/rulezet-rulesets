rule TTP_XOR_QUAD_CurrentVersionRun_d6d9 {
  strings:
    $key_d6d9 = { 85 b6 [2] a1 b8 [2] 8a 94 [2] a4 b6 [2] b0 ad [2] bf b7 [2] a1 aa [2] a3 ab [2] b8 ad [2] a4 aa [2] b8 85 }

  condition:
    any of them
}