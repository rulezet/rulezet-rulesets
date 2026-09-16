rule TTP_XOR_MULT_DOSStub_3bce {
  strings:
    $key_3bce = { 6f a6 [2] 1b be [2] 5c bc [2] 1b ad [2] 55 a1 [2] 59 ab [2] 4e a0 [2] 55 ee [2] 68 }

  condition:
    any of them
}