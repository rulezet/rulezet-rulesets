rule TTP_XOR_MULT_DOSStub_0bce {
  strings:
    $key_0bce = { 5f a6 [2] 2b be [2] 6c bc [2] 2b ad [2] 65 a1 [2] 69 ab [2] 7e a0 [2] 65 ee [2] 58 }

  condition:
    any of them
}