rule TTP_XOR_MULT_DOSStub_6296 {
  strings:
    $key_6296 = { 36 fe [2] 42 e6 [2] 05 e4 [2] 42 f5 [2] 0c f9 [2] 00 f3 [2] 17 f8 [2] 0c b6 [2] 31 }

  condition:
    any of them
}