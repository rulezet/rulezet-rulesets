rule TTP_XOR_MULT_DOSStub_5a83 {
  strings:
    $key_5a83 = { 0e eb [2] 7a f3 [2] 3d f1 [2] 7a e0 [2] 34 ec [2] 38 e6 [2] 2f ed [2] 34 a3 [2] 09 }

  condition:
    any of them
}