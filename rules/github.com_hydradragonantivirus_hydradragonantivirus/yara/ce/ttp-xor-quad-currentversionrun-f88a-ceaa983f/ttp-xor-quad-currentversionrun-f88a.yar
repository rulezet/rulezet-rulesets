rule TTP_XOR_QUAD_CurrentVersionRun_f88a {
  strings:
    $key_f88a = { ab e5 [2] 8f eb [2] a4 c7 [2] 8a e5 [2] 9e fe [2] 91 e4 [2] 8f f9 [2] 8d f8 [2] 96 fe [2] 8a f9 [2] 96 d6 }

  condition:
    any of them
}