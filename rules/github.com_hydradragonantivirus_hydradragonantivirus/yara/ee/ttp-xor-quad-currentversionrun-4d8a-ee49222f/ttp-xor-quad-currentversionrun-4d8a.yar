rule TTP_XOR_QUAD_CurrentVersionRun_4d8a {
  strings:
    $key_4d8a = { 1e e5 [2] 3a eb [2] 11 c7 [2] 3f e5 [2] 2b fe [2] 24 e4 [2] 3a f9 [2] 38 f8 [2] 23 fe [2] 3f f9 [2] 23 d6 }

  condition:
    any of them
}