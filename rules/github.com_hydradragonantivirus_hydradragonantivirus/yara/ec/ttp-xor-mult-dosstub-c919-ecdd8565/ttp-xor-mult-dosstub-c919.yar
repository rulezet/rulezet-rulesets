rule TTP_XOR_MULT_DOSStub_c919 {
  strings:
    $key_c919 = { 9d 71 [2] e9 69 [2] ae 6b [2] e9 7a [2] a7 76 [2] ab 7c [2] bc 77 [2] a7 39 [2] 9a }

  condition:
    any of them
}