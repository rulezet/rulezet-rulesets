rule TTP_XOR_MULT_DOSStub_c379 {
  strings:
    $key_c379 = { 97 11 [2] e3 09 [2] a4 0b [2] e3 1a [2] ad 16 [2] a1 1c [2] b6 17 [2] ad 59 [2] 90 }

  condition:
    any of them
}