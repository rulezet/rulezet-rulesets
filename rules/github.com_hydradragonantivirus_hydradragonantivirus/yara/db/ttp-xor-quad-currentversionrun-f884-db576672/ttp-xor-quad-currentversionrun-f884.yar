rule TTP_XOR_QUAD_CurrentVersionRun_f884 {
  strings:
    $key_f884 = { ab eb [2] 8f e5 [2] a4 c9 [2] 8a eb [2] 9e f0 [2] 91 ea [2] 8f f7 [2] 8d f6 [2] 96 f0 [2] 8a f7 [2] 96 d8 }

  condition:
    any of them
}