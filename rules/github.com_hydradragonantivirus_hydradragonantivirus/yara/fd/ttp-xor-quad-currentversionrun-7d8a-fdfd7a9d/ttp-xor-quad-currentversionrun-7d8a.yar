rule TTP_XOR_QUAD_CurrentVersionRun_7d8a {
  strings:
    $key_7d8a = { 2e e5 [2] 0a eb [2] 21 c7 [2] 0f e5 [2] 1b fe [2] 14 e4 [2] 0a f9 [2] 08 f8 [2] 13 fe [2] 0f f9 [2] 13 d6 }

  condition:
    any of them
}