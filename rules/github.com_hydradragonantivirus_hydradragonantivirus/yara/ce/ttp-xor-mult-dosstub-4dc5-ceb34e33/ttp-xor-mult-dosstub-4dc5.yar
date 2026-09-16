rule TTP_XOR_MULT_DOSStub_4dc5 {
  strings:
    $key_4dc5 = { 19 ad [2] 6d b5 [2] 2a b7 [2] 6d a6 [2] 23 aa [2] 2f a0 [2] 38 ab [2] 23 e5 [2] 1e }

  condition:
    any of them
}