rule TTP_XOR_MULT_DOSStub_dc5a {
  strings:
    $key_dc5a = { 88 32 [2] fc 2a [2] bb 28 [2] fc 39 [2] b2 35 [2] be 3f [2] a9 34 [2] b2 7a [2] 8f }

  condition:
    any of them
}