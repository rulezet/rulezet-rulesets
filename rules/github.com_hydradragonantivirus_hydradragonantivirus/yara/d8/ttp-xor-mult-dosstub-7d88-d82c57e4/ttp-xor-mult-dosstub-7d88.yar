rule TTP_XOR_MULT_DOSStub_7d88 {
  strings:
    $key_7d88 = { 29 e0 [2] 5d f8 [2] 1a fa [2] 5d eb [2] 13 e7 [2] 1f ed [2] 08 e6 [2] 13 a8 [2] 2e }

  condition:
    any of them
}