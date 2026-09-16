rule TTP_XOR_MULT_DOSStub_7783 {
  strings:
    $key_7783 = { 23 eb [2] 57 f3 [2] 10 f1 [2] 57 e0 [2] 19 ec [2] 15 e6 [2] 02 ed [2] 19 a3 [2] 24 }

  condition:
    any of them
}