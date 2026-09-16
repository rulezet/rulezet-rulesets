rule TTP_XOR_MULT_DOSStub_c992 {
  strings:
    $key_c992 = { 9d fa [2] e9 e2 [2] ae e0 [2] e9 f1 [2] a7 fd [2] ab f7 [2] bc fc [2] a7 b2 [2] 9a }

  condition:
    any of them
}