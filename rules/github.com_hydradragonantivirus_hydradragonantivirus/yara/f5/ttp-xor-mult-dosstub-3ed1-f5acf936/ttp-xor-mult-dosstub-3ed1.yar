rule TTP_XOR_MULT_DOSStub_3ed1 {
  strings:
    $key_3ed1 = { 6a b9 [2] 1e a1 [2] 59 a3 [2] 1e b2 [2] 50 be [2] 5c b4 [2] 4b bf [2] 50 f1 [2] 6d }

  condition:
    any of them
}