rule TTP_XOR_MULT_DOSStub_e782 {
  strings:
    $key_e782 = { b3 ea [2] c7 f2 [2] 80 f0 [2] c7 e1 [2] 89 ed [2] 85 e7 [2] 92 ec [2] 89 a2 [2] b4 }

  condition:
    any of them
}