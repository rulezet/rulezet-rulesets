rule TTP_XOR_MULT_DOSStub_8683 {
  strings:
    $key_8683 = { d2 eb [2] a6 f3 [2] e1 f1 [2] a6 e0 [2] e8 ec [2] e4 e6 [2] f3 ed [2] e8 a3 [2] d5 }

  condition:
    any of them
}