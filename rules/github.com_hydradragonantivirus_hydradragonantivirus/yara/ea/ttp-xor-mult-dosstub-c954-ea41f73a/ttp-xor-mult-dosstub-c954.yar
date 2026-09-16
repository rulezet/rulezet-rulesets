rule TTP_XOR_MULT_DOSStub_c954 {
  strings:
    $key_c954 = { 9d 3c [2] e9 24 [2] ae 26 [2] e9 37 [2] a7 3b [2] ab 31 [2] bc 3a [2] a7 74 [2] 9a }

  condition:
    any of them
}