rule TTP_XOR_MULT_DOSStub_0682 {
  strings:
    $key_0682 = { 52 ea [2] 26 f2 [2] 61 f0 [2] 26 e1 [2] 68 ed [2] 64 e7 [2] 73 ec [2] 68 a2 [2] 55 }

  condition:
    any of them
}