rule TTP_XOR_MULT_DOSStub_2a85 {
  strings:
    $key_2a85 = { 7e ed [2] 0a f5 [2] 4d f7 [2] 0a e6 [2] 44 ea [2] 48 e0 [2] 5f eb [2] 44 a5 [2] 79 }

  condition:
    any of them
}