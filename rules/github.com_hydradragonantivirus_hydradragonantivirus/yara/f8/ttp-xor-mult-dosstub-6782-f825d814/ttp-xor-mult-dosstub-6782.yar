rule TTP_XOR_MULT_DOSStub_6782 {
  strings:
    $key_6782 = { 33 ea [2] 47 f2 [2] 00 f0 [2] 47 e1 [2] 09 ed [2] 05 e7 [2] 12 ec [2] 09 a2 [2] 34 }

  condition:
    any of them
}