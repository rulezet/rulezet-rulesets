rule TTP_XOR_MULT_DOSStub_f082 {
  strings:
    $key_f082 = { a4 ea [2] d0 f2 [2] 97 f0 [2] d0 e1 [2] 9e ed [2] 92 e7 [2] 85 ec [2] 9e a2 [2] a3 }

  condition:
    any of them
}