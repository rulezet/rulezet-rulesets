rule TTP_XOR_MULT_DOSStub_d223 {
  strings:
    $key_d223 = { 86 4b [2] f2 53 [2] b5 51 [2] f2 40 [2] bc 4c [2] b0 46 [2] a7 4d [2] bc 03 [2] 81 }

  condition:
    any of them
}