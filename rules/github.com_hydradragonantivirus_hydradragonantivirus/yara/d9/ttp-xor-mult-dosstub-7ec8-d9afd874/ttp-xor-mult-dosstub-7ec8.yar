rule TTP_XOR_MULT_DOSStub_7ec8 {
  strings:
    $key_7ec8 = { 2a a0 [2] 5e b8 [2] 19 ba [2] 5e ab [2] 10 a7 [2] 1c ad [2] 0b a6 [2] 10 e8 [2] 2d }

  condition:
    any of them
}