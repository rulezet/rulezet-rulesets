rule TTP_XOR_MULT_DOSStub_dc16 {
  strings:
    $key_dc16 = { 88 7e [2] fc 66 [2] bb 64 [2] fc 75 [2] b2 79 [2] be 73 [2] a9 78 [2] b2 36 [2] 8f }

  condition:
    any of them
}