rule TTP_XOR_MULT_DOSStub_7fd8 {
  strings:
    $key_7fd8 = { 2b b0 [2] 5f a8 [2] 18 aa [2] 5f bb [2] 11 b7 [2] 1d bd [2] 0a b6 [2] 11 f8 [2] 2c }

  condition:
    any of them
}