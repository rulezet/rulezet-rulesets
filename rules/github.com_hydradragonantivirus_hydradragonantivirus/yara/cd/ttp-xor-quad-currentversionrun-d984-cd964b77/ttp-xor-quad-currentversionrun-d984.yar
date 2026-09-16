rule TTP_XOR_QUAD_CurrentVersionRun_d984 {
  strings:
    $key_d984 = { 8a eb [2] ae e5 [2] 85 c9 [2] ab eb [2] bf f0 [2] b0 ea [2] ae f7 [2] ac f6 [2] b7 f0 [2] ab f7 [2] b7 d8 }

  condition:
    any of them
}