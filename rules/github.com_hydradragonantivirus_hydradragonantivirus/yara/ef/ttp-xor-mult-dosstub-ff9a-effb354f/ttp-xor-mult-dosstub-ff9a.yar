rule TTP_XOR_MULT_DOSStub_ff9a {
  strings:
    $key_ff9a = { ab f2 [2] df ea [2] 98 e8 [2] df f9 [2] 91 f5 [2] 9d ff [2] 8a f4 [2] 91 ba [2] ac }

  condition:
    any of them
}