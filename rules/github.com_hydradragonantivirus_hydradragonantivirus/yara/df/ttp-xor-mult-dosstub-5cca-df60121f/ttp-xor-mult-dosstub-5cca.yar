rule TTP_XOR_MULT_DOSStub_5cca {
  strings:
    $key_5cca = { 08 a2 [2] 7c ba [2] 3b b8 [2] 7c a9 [2] 32 a5 [2] 3e af [2] 29 a4 [2] 32 ea [2] 0f }

  condition:
    any of them
}