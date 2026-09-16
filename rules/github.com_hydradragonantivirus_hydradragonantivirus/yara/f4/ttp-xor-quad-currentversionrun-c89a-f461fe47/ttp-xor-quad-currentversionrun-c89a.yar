rule TTP_XOR_QUAD_CurrentVersionRun_c89a {
  strings:
    $key_c89a = { 9b f5 [2] bf fb [2] 94 d7 [2] ba f5 [2] ae ee [2] a1 f4 [2] bf e9 [2] bd e8 [2] a6 ee [2] ba e9 [2] a6 c6 }

  condition:
    any of them
}