rule TTP_XOR_MULT_DOSStub_d22f {
  strings:
    $key_d22f = { 86 47 [2] f2 5f [2] b5 5d [2] f2 4c [2] bc 40 [2] b0 4a [2] a7 41 [2] bc 0f [2] 81 }

  condition:
    any of them
}