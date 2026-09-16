rule TTP_XOR_MULT_DOSStub_c933 {
  strings:
    $key_c933 = { 9d 5b [2] e9 43 [2] ae 41 [2] e9 50 [2] a7 5c [2] ab 56 [2] bc 5d [2] a7 13 [2] 9a }

  condition:
    any of them
}