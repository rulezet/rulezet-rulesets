rule TTP_XOR_QUAD_CurrentVersionRun_c4d9 {
  strings:
    $key_c4d9 = { 97 b6 [2] b3 b8 [2] 98 94 [2] b6 b6 [2] a2 ad [2] ad b7 [2] b3 aa [2] b1 ab [2] aa ad [2] b6 aa [2] aa 85 }

  condition:
    any of them
}