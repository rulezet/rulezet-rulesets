rule TTP_XOR_QUAD_CurrentVersionRun_2a8a {
  strings:
    $key_2a8a = { 79 e5 [2] 5d eb [2] 76 c7 [2] 58 e5 [2] 4c fe [2] 43 e4 [2] 5d f9 [2] 5f f8 [2] 44 fe [2] 58 f9 [2] 44 d6 }

  condition:
    any of them
}