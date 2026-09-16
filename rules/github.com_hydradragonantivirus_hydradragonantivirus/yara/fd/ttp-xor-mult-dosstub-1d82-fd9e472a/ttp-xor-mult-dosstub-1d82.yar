rule TTP_XOR_MULT_DOSStub_1d82 {
  strings:
    $key_1d82 = { 49 ea [2] 3d f2 [2] 7a f0 [2] 3d e1 [2] 73 ed [2] 7f e7 [2] 68 ec [2] 73 a2 [2] 4e }

  condition:
    any of them
}