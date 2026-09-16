rule TTP_XOR_MULT_DOSStub_ff84 {
  strings:
    $key_ff84 = { ab ec [2] df f4 [2] 98 f6 [2] df e7 [2] 91 eb [2] 9d e1 [2] 8a ea [2] 91 a4 [2] ac }

  condition:
    any of them
}