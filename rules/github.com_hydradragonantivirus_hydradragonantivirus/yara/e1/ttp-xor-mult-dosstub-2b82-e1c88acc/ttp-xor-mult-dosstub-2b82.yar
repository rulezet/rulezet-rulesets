rule TTP_XOR_MULT_DOSStub_2b82 {
  strings:
    $key_2b82 = { 7f ea [2] 0b f2 [2] 4c f0 [2] 0b e1 [2] 45 ed [2] 49 e7 [2] 5e ec [2] 45 a2 [2] 78 }

  condition:
    any of them
}