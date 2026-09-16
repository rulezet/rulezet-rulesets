rule TTP_XOR_QUAD_CurrentVersionRun_1d8a {
  strings:
    $key_1d8a = { 4e e5 [2] 6a eb [2] 41 c7 [2] 6f e5 [2] 7b fe [2] 74 e4 [2] 6a f9 [2] 68 f8 [2] 73 fe [2] 6f f9 [2] 73 d6 }

  condition:
    any of them
}