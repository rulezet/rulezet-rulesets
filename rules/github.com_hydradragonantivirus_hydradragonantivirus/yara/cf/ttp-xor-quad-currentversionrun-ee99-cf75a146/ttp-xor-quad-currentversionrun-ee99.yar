rule TTP_XOR_QUAD_CurrentVersionRun_ee99 {
  strings:
    $key_ee99 = { bd f6 [2] 99 f8 [2] b2 d4 [2] 9c f6 [2] 88 ed [2] 87 f7 [2] 99 ea [2] 9b eb [2] 80 ed [2] 9c ea [2] 80 c5 }

  condition:
    any of them
}