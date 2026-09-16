rule TTP_XOR_MULT_DOSStub_18d0 {
  strings:
    $key_18d0 = { 4c b8 [2] 38 a0 [2] 7f a2 [2] 38 b3 [2] 76 bf [2] 7a b5 [2] 6d be [2] 76 f0 [2] 4b }

  condition:
    any of them
}