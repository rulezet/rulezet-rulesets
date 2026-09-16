rule TTP_XOR_MULT_DOSStub_d218 {
  strings:
    $key_d218 = { 86 70 [2] f2 68 [2] b5 6a [2] f2 7b [2] bc 77 [2] b0 7d [2] a7 76 [2] bc 38 [2] 81 }

  condition:
    any of them
}