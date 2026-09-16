rule TTP_XOR_QUAD_CurrentVersionRun_fb9a {
  strings:
    $key_fb9a = { a8 f5 [2] 8c fb [2] a7 d7 [2] 89 f5 [2] 9d ee [2] 92 f4 [2] 8c e9 [2] 8e e8 [2] 95 ee [2] 89 e9 [2] 95 c6 }

  condition:
    any of them
}