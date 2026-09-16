rule TTP_XOR_MULT_DOSStub_d2dd {
  strings:
    $key_d2dd = { 86 b5 [2] f2 ad [2] b5 af [2] f2 be [2] bc b2 [2] b0 b8 [2] a7 b3 [2] bc fd [2] 81 }

  condition:
    any of them
}