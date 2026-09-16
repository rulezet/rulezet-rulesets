rule TTP_XOR_MULT_DOSStub_5bce {
  strings:
    $key_5bce = { 0f a6 [2] 7b be [2] 3c bc [2] 7b ad [2] 35 a1 [2] 39 ab [2] 2e a0 [2] 35 ee [2] 08 }

  condition:
    any of them
}