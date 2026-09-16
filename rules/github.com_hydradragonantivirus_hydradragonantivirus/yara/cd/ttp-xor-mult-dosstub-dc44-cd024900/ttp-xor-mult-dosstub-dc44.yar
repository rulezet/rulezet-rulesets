rule TTP_XOR_MULT_DOSStub_dc44 {
  strings:
    $key_dc44 = { 88 2c [2] fc 34 [2] bb 36 [2] fc 27 [2] b2 2b [2] be 21 [2] a9 2a [2] b2 64 [2] 8f }

  condition:
    any of them
}