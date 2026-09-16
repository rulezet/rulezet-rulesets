rule TTP_XOR_MULT_DOSStub_c97f {
  strings:
    $key_c97f = { 9d 17 [2] e9 0f [2] ae 0d [2] e9 1c [2] a7 10 [2] ab 1a [2] bc 11 [2] a7 5f [2] 9a }

  condition:
    any of them
}