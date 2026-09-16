rule TTP_XOR_QUAD_CurrentVersionRun_4f99 {
  strings:
    $key_4f99 = { 1c f6 [2] 38 f8 [2] 13 d4 [2] 3d f6 [2] 29 ed [2] 26 f7 [2] 38 ea [2] 3a eb [2] 21 ed [2] 3d ea [2] 21 c5 }

  condition:
    any of them
}