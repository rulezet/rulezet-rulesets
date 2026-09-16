rule TTP_XOR_MULT_DOSStub_5c82 {
  strings:
    $key_5c82 = { 08 ea [2] 7c f2 [2] 3b f0 [2] 7c e1 [2] 32 ed [2] 3e e7 [2] 29 ec [2] 32 a2 [2] 0f }

  condition:
    any of them
}