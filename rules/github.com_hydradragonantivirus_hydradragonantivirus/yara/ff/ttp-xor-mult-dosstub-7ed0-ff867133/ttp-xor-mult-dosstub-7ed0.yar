rule TTP_XOR_MULT_DOSStub_7ed0 {
  strings:
    $key_7ed0 = { 2a b8 [2] 5e a0 [2] 19 a2 [2] 5e b3 [2] 10 bf [2] 1c b5 [2] 0b be [2] 10 f0 [2] 2d }

  condition:
    any of them
}