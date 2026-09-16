rule TTP_XOR_MULT_DOSStub_c9f3 {
  strings:
    $key_c9f3 = { 9d 9b [2] e9 83 [2] ae 81 [2] e9 90 [2] a7 9c [2] ab 96 [2] bc 9d [2] a7 d3 [2] 9a }

  condition:
    any of them
}