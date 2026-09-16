rule TTP_XOR_MULT_DOSStub_dc61 {
  strings:
    $key_dc61 = { 88 09 [2] fc 11 [2] bb 13 [2] fc 02 [2] b2 0e [2] be 04 [2] a9 0f [2] b2 41 [2] 8f }

  condition:
    any of them
}