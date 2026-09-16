rule TTP_XOR_MULT_DOSStub_3dc5 {
  strings:
    $key_3dc5 = { 69 ad [2] 1d b5 [2] 5a b7 [2] 1d a6 [2] 53 aa [2] 5f a0 [2] 48 ab [2] 53 e5 [2] 6e }

  condition:
    any of them
}