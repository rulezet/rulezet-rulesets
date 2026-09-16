rule TTP_XOR_MULT_DOSStub_dc0e {
  strings:
    $key_dc0e = { 88 66 [2] fc 7e [2] bb 7c [2] fc 6d [2] b2 61 [2] be 6b [2] a9 60 [2] b2 2e [2] 8f }

  condition:
    any of them
}