rule TTP_XOR_MULT_DOSStub_c990 {
  strings:
    $key_c990 = { 9d f8 [2] e9 e0 [2] ae e2 [2] e9 f3 [2] a7 ff [2] ab f5 [2] bc fe [2] a7 b0 [2] 9a }

  condition:
    any of them
}