rule TTP_XOR_MULT_DOSStub_dc01 {
  strings:
    $key_dc01 = { 88 69 [2] fc 71 [2] bb 73 [2] fc 62 [2] b2 6e [2] be 64 [2] a9 6f [2] b2 21 [2] 8f }

  condition:
    any of them
}