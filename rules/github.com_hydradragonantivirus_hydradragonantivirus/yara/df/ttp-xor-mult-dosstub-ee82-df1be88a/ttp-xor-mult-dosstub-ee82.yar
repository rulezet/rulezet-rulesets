rule TTP_XOR_MULT_DOSStub_ee82 {
  strings:
    $key_ee82 = { ba ea [2] ce f2 [2] 89 f0 [2] ce e1 [2] 80 ed [2] 8c e7 [2] 9b ec [2] 80 a2 [2] bd }

  condition:
    any of them
}