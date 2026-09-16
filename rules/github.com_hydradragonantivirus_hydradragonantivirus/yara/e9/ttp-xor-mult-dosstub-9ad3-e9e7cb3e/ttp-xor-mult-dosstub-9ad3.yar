rule TTP_XOR_MULT_DOSStub_9ad3 {
  strings:
    $key_9ad3 = { ce bb [2] ba a3 [2] fd a1 [2] ba b0 [2] f4 bc [2] f8 b6 [2] ef bd [2] f4 f3 [2] c9 }

  condition:
    any of them
}