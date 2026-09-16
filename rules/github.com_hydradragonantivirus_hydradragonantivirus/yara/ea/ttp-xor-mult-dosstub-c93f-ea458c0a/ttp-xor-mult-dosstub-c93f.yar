rule TTP_XOR_MULT_DOSStub_c93f {
  strings:
    $key_c93f = { 9d 57 [2] e9 4f [2] ae 4d [2] e9 5c [2] a7 50 [2] ab 5a [2] bc 51 [2] a7 1f [2] 9a }

  condition:
    any of them
}