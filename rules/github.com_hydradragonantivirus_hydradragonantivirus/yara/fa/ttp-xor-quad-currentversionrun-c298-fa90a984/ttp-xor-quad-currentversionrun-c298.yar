rule TTP_XOR_QUAD_CurrentVersionRun_c298 {
  strings:
    $key_c298 = { 91 f7 [2] b5 f9 [2] 9e d5 [2] b0 f7 [2] a4 ec [2] ab f6 [2] b5 eb [2] b7 ea [2] ac ec [2] b0 eb [2] ac c4 }

  condition:
    any of them
}