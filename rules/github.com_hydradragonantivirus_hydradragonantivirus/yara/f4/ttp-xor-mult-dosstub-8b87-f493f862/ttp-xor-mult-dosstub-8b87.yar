rule TTP_XOR_MULT_DOSStub_8b87 {
  strings:
    $key_8b87 = { df ef [2] ab f7 [2] ec f5 [2] ab e4 [2] e5 e8 [2] e9 e2 [2] fe e9 [2] e5 a7 [2] d8 }

  condition:
    any of them
}