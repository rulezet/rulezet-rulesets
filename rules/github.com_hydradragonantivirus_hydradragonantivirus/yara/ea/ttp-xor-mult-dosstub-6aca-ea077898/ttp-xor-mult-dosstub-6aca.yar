rule TTP_XOR_MULT_DOSStub_6aca {
  strings:
    $key_6aca = { 3e a2 [2] 4a ba [2] 0d b8 [2] 4a a9 [2] 04 a5 [2] 08 af [2] 1f a4 [2] 04 ea [2] 39 }

  condition:
    any of them
}