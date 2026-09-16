rule TTP_XOR_MULT_DOSStub_5682 {
  strings:
    $key_5682 = { 02 ea [2] 76 f2 [2] 31 f0 [2] 76 e1 [2] 38 ed [2] 34 e7 [2] 23 ec [2] 38 a2 [2] 05 }

  condition:
    any of them
}