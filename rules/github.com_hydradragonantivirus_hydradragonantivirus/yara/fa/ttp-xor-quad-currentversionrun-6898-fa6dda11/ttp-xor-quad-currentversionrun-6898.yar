rule TTP_XOR_QUAD_CurrentVersionRun_6898 {
  strings:
    $key_6898 = { 3b f7 [2] 1f f9 [2] 34 d5 [2] 1a f7 [2] 0e ec [2] 01 f6 [2] 1f eb [2] 1d ea [2] 06 ec [2] 1a eb [2] 06 c4 }

  condition:
    any of them
}