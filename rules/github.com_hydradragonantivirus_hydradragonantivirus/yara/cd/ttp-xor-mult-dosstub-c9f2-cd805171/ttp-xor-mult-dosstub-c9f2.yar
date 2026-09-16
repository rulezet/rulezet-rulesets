rule TTP_XOR_MULT_DOSStub_c9f2 {
  strings:
    $key_c9f2 = { 9d 9a [2] e9 82 [2] ae 80 [2] e9 91 [2] a7 9d [2] ab 97 [2] bc 9c [2] a7 d2 [2] 9a }

  condition:
    any of them
}