rule TTP_XOR_MULT_DOSStub_c977 {
  strings:
    $key_c977 = { 9d 1f [2] e9 07 [2] ae 05 [2] e9 14 [2] a7 18 [2] ab 12 [2] bc 19 [2] a7 57 [2] 9a }

  condition:
    any of them
}