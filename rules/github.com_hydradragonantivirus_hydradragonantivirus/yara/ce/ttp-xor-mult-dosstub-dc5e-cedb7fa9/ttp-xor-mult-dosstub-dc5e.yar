rule TTP_XOR_MULT_DOSStub_dc5e {
  strings:
    $key_dc5e = { 88 36 [2] fc 2e [2] bb 2c [2] fc 3d [2] b2 31 [2] be 3b [2] a9 30 [2] b2 7e [2] 8f }

  condition:
    any of them
}