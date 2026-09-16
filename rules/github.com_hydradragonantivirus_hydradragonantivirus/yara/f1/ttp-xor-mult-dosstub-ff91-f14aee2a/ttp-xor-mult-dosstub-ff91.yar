rule TTP_XOR_MULT_DOSStub_ff91 {
  strings:
    $key_ff91 = { ab f9 [2] df e1 [2] 98 e3 [2] df f2 [2] 91 fe [2] 9d f4 [2] 8a ff [2] 91 b1 [2] ac }

  condition:
    any of them
}