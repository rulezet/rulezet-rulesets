rule TTP_XOR_MULT_DOSStub_c944 {
  strings:
    $key_c944 = { 9d 2c [2] e9 34 [2] ae 36 [2] e9 27 [2] a7 2b [2] ab 21 [2] bc 2a [2] a7 64 [2] 9a }

  condition:
    any of them
}