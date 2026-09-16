rule TTP_XOR_QUAD_CurrentVersionRun_d498 {
  strings:
    $key_d498 = { 87 f7 [2] a3 f9 [2] 88 d5 [2] a6 f7 [2] b2 ec [2] bd f6 [2] a3 eb [2] a1 ea [2] ba ec [2] a6 eb [2] ba c4 }

  condition:
    any of them
}