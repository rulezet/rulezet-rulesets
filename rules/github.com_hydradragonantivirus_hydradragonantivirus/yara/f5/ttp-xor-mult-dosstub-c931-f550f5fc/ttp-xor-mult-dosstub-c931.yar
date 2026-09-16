rule TTP_XOR_MULT_DOSStub_c931 {
  strings:
    $key_c931 = { 9d 59 [2] e9 41 [2] ae 43 [2] e9 52 [2] a7 5e [2] ab 54 [2] bc 5f [2] a7 11 [2] 9a }

  condition:
    any of them
}