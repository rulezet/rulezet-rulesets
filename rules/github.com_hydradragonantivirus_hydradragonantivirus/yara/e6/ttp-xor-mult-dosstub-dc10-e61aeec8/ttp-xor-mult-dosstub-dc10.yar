rule TTP_XOR_MULT_DOSStub_dc10 {
  strings:
    $key_dc10 = { 88 78 [2] fc 60 [2] bb 62 [2] fc 73 [2] b2 7f [2] be 75 [2] a9 7e [2] b2 30 [2] 8f }

  condition:
    any of them
}