rule TTP_XOR_MULT_DOSStub_59d9 {
  strings:
    $key_59d9 = { 0d b1 [2] 79 a9 [2] 3e ab [2] 79 ba [2] 37 b6 [2] 3b bc [2] 2c b7 [2] 37 f9 [2] 0a }

  condition:
    any of them
}