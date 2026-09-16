rule TTP_XOR_MULT_DOSStub_c559 {
  strings:
    $key_c559 = { 91 31 [2] e5 29 [2] a2 2b [2] e5 3a [2] ab 36 [2] a7 3c [2] b0 37 [2] ab 79 [2] 96 }

  condition:
    any of them
}