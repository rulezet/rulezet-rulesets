rule TTP_XOR_MULT_DOSStub_2cca {
  strings:
    $key_2cca = { 78 a2 [2] 0c ba [2] 4b b8 [2] 0c a9 [2] 42 a5 [2] 4e af [2] 59 a4 [2] 42 ea [2] 7f }

  condition:
    any of them
}