rule TTP_XOR_QUAD_CurrentVersionRun_e49a {
  strings:
    $key_e49a = { b7 f5 [2] 93 fb [2] b8 d7 [2] 96 f5 [2] 82 ee [2] 8d f4 [2] 93 e9 [2] 91 e8 [2] 8a ee [2] 96 e9 [2] 8a c6 }

  condition:
    any of them
}