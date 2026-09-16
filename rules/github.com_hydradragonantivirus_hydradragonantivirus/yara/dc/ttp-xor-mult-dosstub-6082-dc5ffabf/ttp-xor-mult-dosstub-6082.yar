rule TTP_XOR_MULT_DOSStub_6082 {
  strings:
    $key_6082 = { 34 ea [2] 40 f2 [2] 07 f0 [2] 40 e1 [2] 0e ed [2] 02 e7 [2] 15 ec [2] 0e a2 [2] 33 }

  condition:
    any of them
}