rule TTP_XOR_QUAD_CurrentVersionRun_c7c5 {
  strings:
    $key_c7c5 = { 94 aa [2] b0 a4 [2] 9b 88 [2] b5 aa [2] a1 b1 [2] ae ab [2] b0 b6 [2] b2 b7 [2] a9 b1 [2] b5 b6 [2] a9 99 }

  condition:
    any of them
}