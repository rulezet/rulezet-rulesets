rule TTP_XOR_MULT_DOSStub_27ca {
  strings:
    $key_27ca = { 73 a2 [2] 07 ba [2] 40 b8 [2] 07 a9 [2] 49 a5 [2] 45 af [2] 52 a4 [2] 49 ea [2] 74 }

  condition:
    any of them
}