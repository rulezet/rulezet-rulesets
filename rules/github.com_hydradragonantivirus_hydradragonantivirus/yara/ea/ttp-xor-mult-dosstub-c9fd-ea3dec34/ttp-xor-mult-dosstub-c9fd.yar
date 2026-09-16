rule TTP_XOR_MULT_DOSStub_c9fd {
  strings:
    $key_c9fd = { 9d 95 [2] e9 8d [2] ae 8f [2] e9 9e [2] a7 92 [2] ab 98 [2] bc 93 [2] a7 dd [2] 9a }

  condition:
    any of them
}