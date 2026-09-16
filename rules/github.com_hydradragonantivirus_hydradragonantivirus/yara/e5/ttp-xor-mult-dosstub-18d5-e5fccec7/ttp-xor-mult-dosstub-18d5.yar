rule TTP_XOR_MULT_DOSStub_18d5 {
  strings:
    $key_18d5 = { 4c bd [2] 38 a5 [2] 7f a7 [2] 38 b6 [2] 76 ba [2] 7a b0 [2] 6d bb [2] 76 f5 [2] 4b }

  condition:
    any of them
}