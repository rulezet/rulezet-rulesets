rule TTP_XOR_MULT_DOSStub_33ca {
  strings:
    $key_33ca = { 67 a2 [2] 13 ba [2] 54 b8 [2] 13 a9 [2] 5d a5 [2] 51 af [2] 46 a4 [2] 5d ea [2] 60 }

  condition:
    any of them
}