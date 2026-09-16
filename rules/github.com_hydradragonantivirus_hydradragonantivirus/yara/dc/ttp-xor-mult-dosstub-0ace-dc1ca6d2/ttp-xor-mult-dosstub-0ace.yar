rule TTP_XOR_MULT_DOSStub_0ace {
  strings:
    $key_0ace = { 5e a6 [2] 2a be [2] 6d bc [2] 2a ad [2] 64 a1 [2] 68 ab [2] 7f a0 [2] 64 ee [2] 59 }

  condition:
    any of them
}