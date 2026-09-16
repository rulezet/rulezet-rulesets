rule TTP_XOR_QUAD_CurrentVersionRun_c0a9 {
  strings:
    $key_c0a9 = { 93 c6 [2] b7 c8 [2] 9c e4 [2] b2 c6 [2] a6 dd [2] a9 c7 [2] b7 da [2] b5 db [2] ae dd [2] b2 da [2] ae f5 }

  condition:
    any of them
}