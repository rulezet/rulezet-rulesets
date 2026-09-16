rule TTP_XOR_QUAD_CurrentVersionRun_dc9a {
  strings:
    $key_dc9a = { 8f f5 [2] ab fb [2] 80 d7 [2] ae f5 [2] ba ee [2] b5 f4 [2] ab e9 [2] a9 e8 [2] b2 ee [2] ae e9 [2] b2 c6 }

  condition:
    any of them
}