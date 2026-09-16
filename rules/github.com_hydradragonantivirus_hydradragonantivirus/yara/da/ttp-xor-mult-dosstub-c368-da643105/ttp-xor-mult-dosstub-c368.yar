rule TTP_XOR_MULT_DOSStub_c368 {
  strings:
    $key_c368 = { 97 00 [2] e3 18 [2] a4 1a [2] e3 0b [2] ad 07 [2] a1 0d [2] b6 06 [2] ad 48 [2] 90 }

  condition:
    any of them
}