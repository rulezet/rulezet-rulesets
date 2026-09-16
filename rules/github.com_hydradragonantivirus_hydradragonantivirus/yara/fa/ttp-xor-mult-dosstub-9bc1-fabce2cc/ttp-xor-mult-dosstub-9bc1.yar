rule TTP_XOR_MULT_DOSStub_9bc1 {
  strings:
    $key_9bc1 = { cf a9 [2] bb b1 [2] fc b3 [2] bb a2 [2] f5 ae [2] f9 a4 [2] ee af [2] f5 e1 [2] c8 }

  condition:
    any of them
}