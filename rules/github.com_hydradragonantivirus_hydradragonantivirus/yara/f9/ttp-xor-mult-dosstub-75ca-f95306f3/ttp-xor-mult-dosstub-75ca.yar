rule TTP_XOR_MULT_DOSStub_75ca {
  strings:
    $key_75ca = { 21 a2 [2] 55 ba [2] 12 b8 [2] 55 a9 [2] 1b a5 [2] 17 af [2] 00 a4 [2] 1b ea [2] 26 }

  condition:
    any of them
}