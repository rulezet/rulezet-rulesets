rule TTP_XOR_QUAD_CurrentVersionRun_3d9a {
  strings:
    $key_3d9a = { 6e f5 [2] 4a fb [2] 61 d7 [2] 4f f5 [2] 5b ee [2] 54 f4 [2] 4a e9 [2] 48 e8 [2] 53 ee [2] 4f e9 [2] 53 c6 }

  condition:
    any of them
}