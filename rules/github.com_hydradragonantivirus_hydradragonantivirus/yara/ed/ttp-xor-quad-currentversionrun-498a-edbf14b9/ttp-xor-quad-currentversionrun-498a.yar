rule TTP_XOR_QUAD_CurrentVersionRun_498a {
  strings:
    $key_498a = { 1a e5 [2] 3e eb [2] 15 c7 [2] 3b e5 [2] 2f fe [2] 20 e4 [2] 3e f9 [2] 3c f8 [2] 27 fe [2] 3b f9 [2] 27 d6 }

  condition:
    any of them
}