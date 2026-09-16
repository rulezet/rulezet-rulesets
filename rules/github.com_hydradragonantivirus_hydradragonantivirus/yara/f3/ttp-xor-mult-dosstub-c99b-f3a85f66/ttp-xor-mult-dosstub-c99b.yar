rule TTP_XOR_MULT_DOSStub_c99b {
  strings:
    $key_c99b = { 9d f3 [2] e9 eb [2] ae e9 [2] e9 f8 [2] a7 f4 [2] ab fe [2] bc f5 [2] a7 bb [2] 9a }

  condition:
    any of them
}