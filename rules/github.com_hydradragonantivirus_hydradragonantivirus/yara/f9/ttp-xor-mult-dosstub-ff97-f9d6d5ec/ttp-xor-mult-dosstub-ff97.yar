rule TTP_XOR_MULT_DOSStub_ff97 {
  strings:
    $key_ff97 = { ab ff [2] df e7 [2] 98 e5 [2] df f4 [2] 91 f8 [2] 9d f2 [2] 8a f9 [2] 91 b7 [2] ac }

  condition:
    any of them
}