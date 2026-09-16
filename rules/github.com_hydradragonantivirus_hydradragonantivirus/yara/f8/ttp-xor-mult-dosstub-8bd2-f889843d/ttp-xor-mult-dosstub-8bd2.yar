rule TTP_XOR_MULT_DOSStub_8bd2 {
  strings:
    $key_8bd2 = { df ba [2] ab a2 [2] ec a0 [2] ab b1 [2] e5 bd [2] e9 b7 [2] fe bc [2] e5 f2 [2] d8 }

  condition:
    any of them
}