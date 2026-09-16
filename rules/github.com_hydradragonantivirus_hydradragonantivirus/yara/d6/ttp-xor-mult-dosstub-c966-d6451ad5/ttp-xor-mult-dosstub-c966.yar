rule TTP_XOR_MULT_DOSStub_c966 {
  strings:
    $key_c966 = { 9d 0e [2] e9 16 [2] ae 14 [2] e9 05 [2] a7 09 [2] ab 03 [2] bc 08 [2] a7 46 [2] 9a }

  condition:
    any of them
}