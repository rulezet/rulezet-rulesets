rule TTP_XOR_MULT_DOSStub_0ed2 {
  strings:
    $key_0ed2 = { 5a ba [2] 2e a2 [2] 69 a0 [2] 2e b1 [2] 60 bd [2] 6c b7 [2] 7b bc [2] 60 f2 [2] 5d }

  condition:
    any of them
}