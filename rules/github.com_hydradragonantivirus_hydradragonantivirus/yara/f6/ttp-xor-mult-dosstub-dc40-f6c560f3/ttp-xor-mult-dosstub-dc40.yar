rule TTP_XOR_MULT_DOSStub_dc40 {
  strings:
    $key_dc40 = { 88 28 [2] fc 30 [2] bb 32 [2] fc 23 [2] b2 2f [2] be 25 [2] a9 2e [2] b2 60 [2] 8f }

  condition:
    any of them
}