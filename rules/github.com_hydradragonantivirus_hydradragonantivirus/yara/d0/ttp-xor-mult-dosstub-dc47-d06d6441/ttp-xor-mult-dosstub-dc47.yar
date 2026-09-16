rule TTP_XOR_MULT_DOSStub_dc47 {
  strings:
    $key_dc47 = { 88 2f [2] fc 37 [2] bb 35 [2] fc 24 [2] b2 28 [2] be 22 [2] a9 29 [2] b2 67 [2] 8f }

  condition:
    any of them
}