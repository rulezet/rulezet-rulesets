rule TTP_XOR_MULT_DOSStub_d262 {
  strings:
    $key_d262 = { 86 0a [2] f2 12 [2] b5 10 [2] f2 01 [2] bc 0d [2] b0 07 [2] a7 0c [2] bc 42 [2] 81 }

  condition:
    any of them
}