rule TTP_XOR_MULT_DOSStub_9084 {
  strings:
    $key_9084 = { c4 ec [2] b0 f4 [2] f7 f6 [2] b0 e7 [2] fe eb [2] f2 e1 [2] e5 ea [2] fe a4 [2] c3 }

  condition:
    any of them
}