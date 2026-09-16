rule TTP_XOR_QUAD_CurrentVersionRun_c0a8 {
  strings:
    $key_c0a8 = { 93 c7 [2] b7 c9 [2] 9c e5 [2] b2 c7 [2] a6 dc [2] a9 c6 [2] b7 db [2] b5 da [2] ae dc [2] b2 db [2] ae f4 }

  condition:
    any of them
}