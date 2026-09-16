rule TTP_XOR_MULT_DOSStub_d26a {
  strings:
    $key_d26a = { 86 02 [2] f2 1a [2] b5 18 [2] f2 09 [2] bc 05 [2] b0 0f [2] a7 04 [2] bc 4a [2] 81 }

  condition:
    any of them
}