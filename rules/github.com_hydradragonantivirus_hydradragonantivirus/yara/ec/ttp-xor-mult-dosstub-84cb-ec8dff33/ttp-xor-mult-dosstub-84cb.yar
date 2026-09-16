rule TTP_XOR_MULT_DOSStub_84cb {
  strings:
    $key_84cb = { d0 a3 [2] a4 bb [2] e3 b9 [2] a4 a8 [2] ea a4 [2] e6 ae [2] f1 a5 [2] ea eb [2] d7 }

  condition:
    any of them
}