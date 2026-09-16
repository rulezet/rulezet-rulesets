rule TTP_XOR_MULT_DOSStub_d2ef {
  strings:
    $key_d2ef = { 86 87 [2] f2 9f [2] b5 9d [2] f2 8c [2] bc 80 [2] b0 8a [2] a7 81 [2] bc cf [2] 81 }

  condition:
    any of them
}