rule TTP_XOR_QUAD_CurrentVersionRun_e98a {
  strings:
    $key_e98a = { ba e5 [2] 9e eb [2] b5 c7 [2] 9b e5 [2] 8f fe [2] 80 e4 [2] 9e f9 [2] 9c f8 [2] 87 fe [2] 9b f9 [2] 87 d6 }

  condition:
    any of them
}