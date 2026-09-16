rule TTP_XOR_MULT_DOSStub_c924 {
  strings:
    $key_c924 = { 9d 4c [2] e9 54 [2] ae 56 [2] e9 47 [2] a7 4b [2] ab 41 [2] bc 4a [2] a7 04 [2] 9a }

  condition:
    any of them
}