rule TTP_XOR_MULT_DOSStub_9ac4 {
  strings:
    $key_9ac4 = { ce ac [2] ba b4 [2] fd b6 [2] ba a7 [2] f4 ab [2] f8 a1 [2] ef aa [2] f4 e4 [2] c9 }

  condition:
    any of them
}