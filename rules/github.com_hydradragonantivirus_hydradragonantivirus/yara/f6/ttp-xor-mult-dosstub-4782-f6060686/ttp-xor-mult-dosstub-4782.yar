rule TTP_XOR_MULT_DOSStub_4782 {
  strings:
    $key_4782 = { 13 ea [2] 67 f2 [2] 20 f0 [2] 67 e1 [2] 29 ed [2] 25 e7 [2] 32 ec [2] 29 a2 [2] 14 }

  condition:
    any of them
}