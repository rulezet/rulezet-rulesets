rule TTP_XOR_QUAD_CurrentVersionRun_c898 {
  strings:
    $key_c898 = { 9b f7 [2] bf f9 [2] 94 d5 [2] ba f7 [2] ae ec [2] a1 f6 [2] bf eb [2] bd ea [2] a6 ec [2] ba eb [2] a6 c4 }

  condition:
    any of them
}