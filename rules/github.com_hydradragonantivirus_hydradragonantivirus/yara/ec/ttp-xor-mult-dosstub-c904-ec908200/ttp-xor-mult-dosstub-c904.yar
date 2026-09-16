rule TTP_XOR_MULT_DOSStub_c904 {
  strings:
    $key_c904 = { 9d 6c [2] e9 74 [2] ae 76 [2] e9 67 [2] a7 6b [2] ab 61 [2] bc 6a [2] a7 24 [2] 9a }

  condition:
    any of them
}