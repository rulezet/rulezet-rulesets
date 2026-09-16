rule TTP_XOR_MULT_DOSStub_c942 {
  strings:
    $key_c942 = { 9d 2a [2] e9 32 [2] ae 30 [2] e9 21 [2] a7 2d [2] ab 27 [2] bc 2c [2] a7 62 [2] 9a }

  condition:
    any of them
}