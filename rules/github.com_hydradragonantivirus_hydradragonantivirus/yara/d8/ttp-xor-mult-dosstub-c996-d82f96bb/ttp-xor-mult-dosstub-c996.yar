rule TTP_XOR_MULT_DOSStub_c996 {
  strings:
    $key_c996 = { 9d fe [2] e9 e6 [2] ae e4 [2] e9 f5 [2] a7 f9 [2] ab f3 [2] bc f8 [2] a7 b6 [2] 9a }

  condition:
    any of them
}