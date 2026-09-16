rule TTP_XOR_MULT_DOSStub_9bdf {
  strings:
    $key_9bdf = { cf b7 [2] bb af [2] fc ad [2] bb bc [2] f5 b0 [2] f9 ba [2] ee b1 [2] f5 ff [2] c8 }

  condition:
    any of them
}