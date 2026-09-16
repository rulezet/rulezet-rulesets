rule TTP_XOR_MULT_DOSStub_3fd8 {
  strings:
    $key_3fd8 = { 6b b0 [2] 1f a8 [2] 58 aa [2] 1f bb [2] 51 b7 [2] 5d bd [2] 4a b6 [2] 51 f8 [2] 6c }

  condition:
    any of them
}