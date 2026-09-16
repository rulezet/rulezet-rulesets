rule TTP_XOR_MULT_DOSStub_d2df {
  strings:
    $key_d2df = { 86 b7 [2] f2 af [2] b5 ad [2] f2 bc [2] bc b0 [2] b0 ba [2] a7 b1 [2] bc ff [2] 81 }

  condition:
    any of them
}