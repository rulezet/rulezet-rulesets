rule TTP_XOR_MULT_DOSStub_2c82 {
  strings:
    $key_2c82 = { 78 ea [2] 0c f2 [2] 4b f0 [2] 0c e1 [2] 42 ed [2] 4e e7 [2] 59 ec [2] 42 a2 [2] 7f }

  condition:
    any of them
}