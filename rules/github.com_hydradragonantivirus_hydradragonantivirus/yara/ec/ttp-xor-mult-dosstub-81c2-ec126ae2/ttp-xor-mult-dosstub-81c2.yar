rule TTP_XOR_MULT_DOSStub_81c2 {
  strings:
    $key_81c2 = { d5 aa [2] a1 b2 [2] e6 b0 [2] a1 a1 [2] ef ad [2] e3 a7 [2] f4 ac [2] ef e2 [2] d2 }

  condition:
    any of them
}