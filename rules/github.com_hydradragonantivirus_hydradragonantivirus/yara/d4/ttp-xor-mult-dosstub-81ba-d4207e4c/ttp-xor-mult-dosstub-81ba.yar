rule TTP_XOR_MULT_DOSStub_81ba {
  strings:
    $key_81ba = { d5 d2 [2] a1 ca [2] e6 c8 [2] a1 d9 [2] ef d5 [2] e3 df [2] f4 d4 [2] ef 9a [2] d2 }

  condition:
    any of them
}