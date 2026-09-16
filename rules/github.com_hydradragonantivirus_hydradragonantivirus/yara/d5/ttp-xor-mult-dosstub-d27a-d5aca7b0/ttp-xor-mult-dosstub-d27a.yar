rule TTP_XOR_MULT_DOSStub_d27a {
  strings:
    $key_d27a = { 86 12 [2] f2 0a [2] b5 08 [2] f2 19 [2] bc 15 [2] b0 1f [2] a7 14 [2] bc 5a [2] 81 }

  condition:
    any of them
}