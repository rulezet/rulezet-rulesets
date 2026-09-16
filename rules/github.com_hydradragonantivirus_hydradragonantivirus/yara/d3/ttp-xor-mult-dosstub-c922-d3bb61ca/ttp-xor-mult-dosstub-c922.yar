rule TTP_XOR_MULT_DOSStub_c922 {
  strings:
    $key_c922 = { 9d 4a [2] e9 52 [2] ae 50 [2] e9 41 [2] a7 4d [2] ab 47 [2] bc 4c [2] a7 02 [2] 9a }

  condition:
    any of them
}