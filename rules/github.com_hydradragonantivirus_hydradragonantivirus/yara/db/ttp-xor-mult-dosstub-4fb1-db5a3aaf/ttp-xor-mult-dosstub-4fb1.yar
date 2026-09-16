rule TTP_XOR_MULT_DOSStub_4fb1 {
  strings:
    $key_4fb1 = { 1b d9 [2] 6f c1 [2] 28 c3 [2] 6f d2 [2] 21 de [2] 2d d4 [2] 3a df [2] 21 91 [2] 1c }

  condition:
    any of them
}