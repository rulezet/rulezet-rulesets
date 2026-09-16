rule TTP_XOR_MULT_DOSStub_dc0b {
  strings:
    $key_dc0b = { 88 63 [2] fc 7b [2] bb 79 [2] fc 68 [2] b2 64 [2] be 6e [2] a9 65 [2] b2 2b [2] 8f }

  condition:
    any of them
}