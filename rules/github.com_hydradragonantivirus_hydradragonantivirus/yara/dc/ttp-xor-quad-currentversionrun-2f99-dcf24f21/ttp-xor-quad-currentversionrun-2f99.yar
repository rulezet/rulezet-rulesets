rule TTP_XOR_QUAD_CurrentVersionRun_2f99 {
  strings:
    $key_2f99 = { 7c f6 [2] 58 f8 [2] 73 d4 [2] 5d f6 [2] 49 ed [2] 46 f7 [2] 58 ea [2] 5a eb [2] 41 ed [2] 5d ea [2] 41 c5 }

  condition:
    any of them
}