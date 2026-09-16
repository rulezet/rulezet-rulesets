rule TTP_XOR_MULT_DOSStub_68d4 {
  strings:
    $key_68d4 = { 3c bc [2] 48 a4 [2] 0f a6 [2] 48 b7 [2] 06 bb [2] 0a b1 [2] 1d ba [2] 06 f4 [2] 3b }

  condition:
    any of them
}