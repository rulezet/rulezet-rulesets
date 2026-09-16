rule TTP_XOR_MULT_DOSStub_3d85 {
  strings:
    $key_3d85 = { 69 ed [2] 1d f5 [2] 5a f7 [2] 1d e6 [2] 53 ea [2] 5f e0 [2] 48 eb [2] 53 a5 [2] 6e }

  condition:
    any of them
}