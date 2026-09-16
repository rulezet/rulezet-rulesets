rule TTP_XOR_MULT_DOSStub_dc2e {
  strings:
    $key_dc2e = { 88 46 [2] fc 5e [2] bb 5c [2] fc 4d [2] b2 41 [2] be 4b [2] a9 40 [2] b2 0e [2] 8f }

  condition:
    any of them
}