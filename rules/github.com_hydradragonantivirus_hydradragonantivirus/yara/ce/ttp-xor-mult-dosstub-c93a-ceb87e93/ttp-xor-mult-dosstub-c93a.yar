rule TTP_XOR_MULT_DOSStub_c93a {
  strings:
    $key_c93a = { 9d 52 [2] e9 4a [2] ae 48 [2] e9 59 [2] a7 55 [2] ab 5f [2] bc 54 [2] a7 1a [2] 9a }

  condition:
    any of them
}