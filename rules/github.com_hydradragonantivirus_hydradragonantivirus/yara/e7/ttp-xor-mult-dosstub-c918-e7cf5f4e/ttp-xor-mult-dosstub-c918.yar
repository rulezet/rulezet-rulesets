rule TTP_XOR_MULT_DOSStub_c918 {
  strings:
    $key_c918 = { 9d 70 [2] e9 68 [2] ae 6a [2] e9 7b [2] a7 77 [2] ab 7d [2] bc 76 [2] a7 38 [2] 9a }

  condition:
    any of them
}