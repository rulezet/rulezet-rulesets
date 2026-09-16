rule TTP_XOR_QUAD_CurrentVersionRun_eb9a {
  strings:
    $key_eb9a = { b8 f5 [2] 9c fb [2] b7 d7 [2] 99 f5 [2] 8d ee [2] 82 f4 [2] 9c e9 [2] 9e e8 [2] 85 ee [2] 99 e9 [2] 85 c6 }

  condition:
    any of them
}