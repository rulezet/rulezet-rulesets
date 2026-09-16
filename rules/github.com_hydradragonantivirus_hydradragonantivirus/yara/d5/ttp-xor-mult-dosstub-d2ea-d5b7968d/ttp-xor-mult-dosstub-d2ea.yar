rule TTP_XOR_MULT_DOSStub_d2ea {
  strings:
    $key_d2ea = { 86 82 [2] f2 9a [2] b5 98 [2] f2 89 [2] bc 85 [2] b0 8f [2] a7 84 [2] bc ca [2] 81 }

  condition:
    any of them
}