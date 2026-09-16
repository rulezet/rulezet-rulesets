rule TTP_XOR_MULT_DOSStub_d2f3 {
  strings:
    $key_d2f3 = { 86 9b [2] f2 83 [2] b5 81 [2] f2 90 [2] bc 9c [2] b0 96 [2] a7 9d [2] bc d3 [2] 81 }

  condition:
    any of them
}