rule TTP_XOR_MULT_DOSStub_58d5 {
  strings:
    $key_58d5 = { 0c bd [2] 78 a5 [2] 3f a7 [2] 78 b6 [2] 36 ba [2] 3a b0 [2] 2d bb [2] 36 f5 [2] 0b }

  condition:
    any of them
}