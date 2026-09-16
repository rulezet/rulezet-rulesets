rule TTP_XOR_MULT_DOSStub_dc7b {
  strings:
    $key_dc7b = { 88 13 [2] fc 0b [2] bb 09 [2] fc 18 [2] b2 14 [2] be 1e [2] a9 15 [2] b2 5b [2] 8f }

  condition:
    any of them
}