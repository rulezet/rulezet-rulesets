rule TTP_XOR_QUAD_CurrentVersionRun_e4b4 {
  strings:
    $key_e4b4 = { b7 db [2] 93 d5 [2] b8 f9 [2] 96 db [2] 82 c0 [2] 8d da [2] 93 c7 [2] 91 c6 [2] 8a c0 [2] 96 c7 [2] 8a e8 }

  condition:
    any of them
}