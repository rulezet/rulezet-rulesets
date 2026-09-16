rule TTP_XOR_QUAD_CurrentVersionRun_e4ba {
  strings:
    $key_e4ba = { b7 d5 [2] 93 db [2] b8 f7 [2] 96 d5 [2] 82 ce [2] 8d d4 [2] 93 c9 [2] 91 c8 [2] 8a ce [2] 96 c9 [2] 8a e6 }

  condition:
    any of them
}