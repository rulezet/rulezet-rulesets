rule TTP_XOR_MULT_DOSStub_c975 {
  strings:
    $key_c975 = { 9d 1d [2] e9 05 [2] ae 07 [2] e9 16 [2] a7 1a [2] ab 10 [2] bc 1b [2] a7 55 [2] 9a }

  condition:
    any of them
}