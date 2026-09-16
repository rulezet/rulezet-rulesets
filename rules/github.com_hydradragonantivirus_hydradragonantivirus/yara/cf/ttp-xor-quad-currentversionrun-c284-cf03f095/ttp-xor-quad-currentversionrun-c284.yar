rule TTP_XOR_QUAD_CurrentVersionRun_c284 {
  strings:
    $key_c284 = { 91 eb [2] b5 e5 [2] 9e c9 [2] b0 eb [2] a4 f0 [2] ab ea [2] b5 f7 [2] b7 f6 [2] ac f0 [2] b0 f7 [2] ac d8 }

  condition:
    any of them
}