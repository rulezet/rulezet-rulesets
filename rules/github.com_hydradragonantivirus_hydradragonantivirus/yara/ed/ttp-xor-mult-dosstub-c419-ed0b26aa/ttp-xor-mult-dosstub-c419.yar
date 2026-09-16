rule TTP_XOR_MULT_DOSStub_c419 {
  strings:
    $key_c419 = { 90 71 [2] e4 69 [2] a3 6b [2] e4 7a [2] aa 76 [2] a6 7c [2] b1 77 [2] aa 39 [2] 97 }

  condition:
    any of them
}