rule TTP_XOR_QUAD_CurrentVersionRun_0d8a {
  strings:
    $key_0d8a = { 5e e5 [2] 7a eb [2] 51 c7 [2] 7f e5 [2] 6b fe [2] 64 e4 [2] 7a f9 [2] 78 f8 [2] 63 fe [2] 7f f9 [2] 63 d6 }

  condition:
    any of them
}