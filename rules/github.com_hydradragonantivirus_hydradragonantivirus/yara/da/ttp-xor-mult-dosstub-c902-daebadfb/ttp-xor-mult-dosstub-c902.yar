rule TTP_XOR_MULT_DOSStub_c902 {
  strings:
    $key_c902 = { 9d 6a [2] e9 72 [2] ae 70 [2] e9 61 [2] a7 6d [2] ab 67 [2] bc 6c [2] a7 22 [2] 9a }

  condition:
    any of them
}