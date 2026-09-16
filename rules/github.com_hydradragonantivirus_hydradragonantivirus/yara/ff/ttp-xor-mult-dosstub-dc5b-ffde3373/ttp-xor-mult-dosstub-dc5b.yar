rule TTP_XOR_MULT_DOSStub_dc5b {
  strings:
    $key_dc5b = { 88 33 [2] fc 2b [2] bb 29 [2] fc 38 [2] b2 34 [2] be 3e [2] a9 35 [2] b2 7b [2] 8f }

  condition:
    any of them
}