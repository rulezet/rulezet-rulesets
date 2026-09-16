rule TTP_XOR_MULT_DOSStub_c99a {
  strings:
    $key_c99a = { 9d f2 [2] e9 ea [2] ae e8 [2] e9 f9 [2] a7 f5 [2] ab ff [2] bc f4 [2] a7 ba [2] 9a }

  condition:
    any of them
}