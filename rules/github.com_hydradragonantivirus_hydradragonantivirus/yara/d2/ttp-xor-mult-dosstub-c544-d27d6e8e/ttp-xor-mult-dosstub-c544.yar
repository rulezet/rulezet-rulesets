rule TTP_XOR_MULT_DOSStub_c544 {
  strings:
    $key_c544 = { 91 2c [2] e5 34 [2] a2 36 [2] e5 27 [2] ab 2b [2] a7 21 [2] b0 2a [2] ab 64 [2] 96 }

  condition:
    any of them
}