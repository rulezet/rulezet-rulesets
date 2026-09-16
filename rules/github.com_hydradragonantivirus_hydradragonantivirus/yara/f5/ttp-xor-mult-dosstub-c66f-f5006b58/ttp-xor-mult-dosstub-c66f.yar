rule TTP_XOR_MULT_DOSStub_c66f {
  strings:
    $key_c66f = { 92 07 [2] e6 1f [2] a1 1d [2] e6 0c [2] a8 00 [2] a4 0a [2] b3 01 [2] a8 4f [2] 95 }

  condition:
    any of them
}