rule TTP_XOR_MULT_DOSStub_e640 {
  strings:
    $key_e640 = { b2 28 [2] c6 30 [2] 81 32 [2] c6 23 [2] 88 2f [2] 84 25 [2] 93 2e [2] 88 60 [2] b5 }

  condition:
    any of them
}