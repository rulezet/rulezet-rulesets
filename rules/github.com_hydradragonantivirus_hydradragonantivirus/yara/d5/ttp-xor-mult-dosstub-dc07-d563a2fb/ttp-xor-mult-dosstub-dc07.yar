rule TTP_XOR_MULT_DOSStub_dc07 {
  strings:
    $key_dc07 = { 88 6f [2] fc 77 [2] bb 75 [2] fc 64 [2] b2 68 [2] be 62 [2] a9 69 [2] b2 27 [2] 8f }

  condition:
    any of them
}