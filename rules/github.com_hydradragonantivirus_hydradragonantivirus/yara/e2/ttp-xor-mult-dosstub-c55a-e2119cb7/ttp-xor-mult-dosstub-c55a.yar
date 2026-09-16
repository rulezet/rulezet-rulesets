rule TTP_XOR_MULT_DOSStub_c55a {
  strings:
    $key_c55a = { 91 32 [2] e5 2a [2] a2 28 [2] e5 39 [2] ab 35 [2] a7 3f [2] b0 34 [2] ab 7a [2] 96 }

  condition:
    any of them
}