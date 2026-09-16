rule TTP_XOR_MULT_DOSStub_9b83 {
  strings:
    $key_9b83 = { cf eb [2] bb f3 [2] fc f1 [2] bb e0 [2] f5 ec [2] f9 e6 [2] ee ed [2] f5 a3 [2] c8 }

  condition:
    any of them
}