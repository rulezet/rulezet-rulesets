rule TTP_XOR_MULT_DOSStub_8483 {
  strings:
    $key_8483 = { d0 eb [2] a4 f3 [2] e3 f1 [2] a4 e0 [2] ea ec [2] e6 e6 [2] f1 ed [2] ea a3 [2] d7 }

  condition:
    any of them
}