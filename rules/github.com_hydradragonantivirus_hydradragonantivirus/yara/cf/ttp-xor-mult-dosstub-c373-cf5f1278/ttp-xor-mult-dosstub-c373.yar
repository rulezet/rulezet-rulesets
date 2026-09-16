rule TTP_XOR_MULT_DOSStub_c373 {
  strings:
    $key_c373 = { 97 1b [2] e3 03 [2] a4 01 [2] e3 10 [2] ad 1c [2] a1 16 [2] b6 1d [2] ad 53 [2] 90 }

  condition:
    any of them
}