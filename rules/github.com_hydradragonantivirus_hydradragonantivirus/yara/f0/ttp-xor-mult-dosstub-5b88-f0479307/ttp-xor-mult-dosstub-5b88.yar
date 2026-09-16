rule TTP_XOR_MULT_DOSStub_5b88 {
  strings:
    $key_5b88 = { 0f e0 [2] 7b f8 [2] 3c fa [2] 7b eb [2] 35 e7 [2] 39 ed [2] 2e e6 [2] 35 a8 [2] 08 }

  condition:
    any of them
}