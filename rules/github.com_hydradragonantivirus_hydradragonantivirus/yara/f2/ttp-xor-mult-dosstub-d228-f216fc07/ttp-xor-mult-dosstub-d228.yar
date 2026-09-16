rule TTP_XOR_MULT_DOSStub_d228 {
  strings:
    $key_d228 = { 86 40 [2] f2 58 [2] b5 5a [2] f2 4b [2] bc 47 [2] b0 4d [2] a7 46 [2] bc 08 [2] 81 }

  condition:
    any of them
}