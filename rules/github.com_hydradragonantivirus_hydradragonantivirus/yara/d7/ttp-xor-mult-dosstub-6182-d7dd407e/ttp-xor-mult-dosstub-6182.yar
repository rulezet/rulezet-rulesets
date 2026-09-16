rule TTP_XOR_MULT_DOSStub_6182 {
  strings:
    $key_6182 = { 35 ea [2] 41 f2 [2] 06 f0 [2] 41 e1 [2] 0f ed [2] 03 e7 [2] 14 ec [2] 0f a2 [2] 32 }

  condition:
    any of them
}