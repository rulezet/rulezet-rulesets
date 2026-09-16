rule TTP_XOR_MULT_DOSStub_5aca {
  strings:
    $key_5aca = { 0e a2 [2] 7a ba [2] 3d b8 [2] 7a a9 [2] 34 a5 [2] 38 af [2] 2f a4 [2] 34 ea [2] 09 }

  condition:
    any of them
}