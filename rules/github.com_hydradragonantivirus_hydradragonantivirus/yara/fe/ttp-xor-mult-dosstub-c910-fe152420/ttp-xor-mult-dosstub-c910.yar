rule TTP_XOR_MULT_DOSStub_c910 {
  strings:
    $key_c910 = { 9d 78 [2] e9 60 [2] ae 62 [2] e9 73 [2] a7 7f [2] ab 75 [2] bc 7e [2] a7 30 [2] 9a }

  condition:
    any of them
}