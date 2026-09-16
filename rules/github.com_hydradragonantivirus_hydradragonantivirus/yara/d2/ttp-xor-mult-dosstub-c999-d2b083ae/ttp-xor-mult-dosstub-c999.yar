rule TTP_XOR_MULT_DOSStub_c999 {
  strings:
    $key_c999 = { 9d f1 [2] e9 e9 [2] ae eb [2] e9 fa [2] a7 f6 [2] ab fc [2] bc f7 [2] a7 b9 [2] 9a }

  condition:
    any of them
}