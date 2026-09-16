rule TTP_XOR_MULT_DOSStub_2fd9 {
  strings:
    $key_2fd9 = { 7b b1 [2] 0f a9 [2] 48 ab [2] 0f ba [2] 41 b6 [2] 4d bc [2] 5a b7 [2] 41 f9 [2] 7c }

  condition:
    any of them
}