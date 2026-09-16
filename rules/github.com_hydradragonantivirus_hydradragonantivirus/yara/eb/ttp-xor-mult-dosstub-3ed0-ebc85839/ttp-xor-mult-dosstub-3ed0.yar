rule TTP_XOR_MULT_DOSStub_3ed0 {
  strings:
    $key_3ed0 = { 6a b8 [2] 1e a0 [2] 59 a2 [2] 1e b3 [2] 50 bf [2] 5c b5 [2] 4b be [2] 50 f0 [2] 6d }

  condition:
    any of them
}