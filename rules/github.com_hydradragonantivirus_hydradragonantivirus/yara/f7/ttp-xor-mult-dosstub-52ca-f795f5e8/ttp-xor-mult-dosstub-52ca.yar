rule TTP_XOR_MULT_DOSStub_52ca {
  strings:
    $key_52ca = { 06 a2 [2] 72 ba [2] 35 b8 [2] 72 a9 [2] 3c a5 [2] 30 af [2] 27 a4 [2] 3c ea [2] 01 }

  condition:
    any of them
}