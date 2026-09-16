rule TTP_XOR_MULT_DOSStub_1e85 {
  strings:
    $key_1e85 = { 4a ed [2] 3e f5 [2] 79 f7 [2] 3e e6 [2] 70 ea [2] 7c e0 [2] 6b eb [2] 70 a5 [2] 4d }

  condition:
    any of them
}