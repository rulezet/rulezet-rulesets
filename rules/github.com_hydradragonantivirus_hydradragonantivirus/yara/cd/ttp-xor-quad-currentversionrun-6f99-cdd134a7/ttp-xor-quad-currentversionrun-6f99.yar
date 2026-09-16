rule TTP_XOR_QUAD_CurrentVersionRun_6f99 {
  strings:
    $key_6f99 = { 3c f6 [2] 18 f8 [2] 33 d4 [2] 1d f6 [2] 09 ed [2] 06 f7 [2] 18 ea [2] 1a eb [2] 01 ed [2] 1d ea [2] 01 c5 }

  condition:
    any of them
}