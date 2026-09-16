rule TTP_XOR_MULT_DOSStub_5b82 {
  strings:
    $key_5b82 = { 0f ea [2] 7b f2 [2] 3c f0 [2] 7b e1 [2] 35 ed [2] 39 e7 [2] 2e ec [2] 35 a2 [2] 08 }

  condition:
    any of them
}