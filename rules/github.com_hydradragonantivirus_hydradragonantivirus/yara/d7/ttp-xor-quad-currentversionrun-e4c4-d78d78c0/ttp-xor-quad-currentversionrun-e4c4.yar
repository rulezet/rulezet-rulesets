rule TTP_XOR_QUAD_CurrentVersionRun_e4c4 {
  strings:
    $key_e4c4 = { b7 ab [2] 93 a5 [2] b8 89 [2] 96 ab [2] 82 b0 [2] 8d aa [2] 93 b7 [2] 91 b6 [2] 8a b0 [2] 96 b7 [2] 8a 98 }

  condition:
    any of them
}