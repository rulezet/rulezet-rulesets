rule TTP_XOR_MULT_DOSStub_0b82 {
  strings:
    $key_0b82 = { 5f ea [2] 2b f2 [2] 6c f0 [2] 2b e1 [2] 65 ed [2] 69 e7 [2] 7e ec [2] 65 a2 [2] 58 }

  condition:
    any of them
}