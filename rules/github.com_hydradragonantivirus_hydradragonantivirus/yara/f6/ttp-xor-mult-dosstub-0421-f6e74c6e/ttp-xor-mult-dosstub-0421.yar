rule TTP_XOR_MULT_DOSStub_0421 {
  strings:
    $key_0421 = { 50 49 [2] 24 51 [2] 63 53 [2] 24 42 [2] 6a 4e [2] 66 44 [2] 71 4f [2] 6a 01 [2] 57 }

  condition:
    any of them
}