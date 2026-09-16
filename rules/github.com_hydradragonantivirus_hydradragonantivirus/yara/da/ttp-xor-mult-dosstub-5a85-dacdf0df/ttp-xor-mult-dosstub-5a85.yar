rule TTP_XOR_MULT_DOSStub_5a85 {
  strings:
    $key_5a85 = { 0e ed [2] 7a f5 [2] 3d f7 [2] 7a e6 [2] 34 ea [2] 38 e0 [2] 2f eb [2] 34 a5 [2] 09 }

  condition:
    any of them
}