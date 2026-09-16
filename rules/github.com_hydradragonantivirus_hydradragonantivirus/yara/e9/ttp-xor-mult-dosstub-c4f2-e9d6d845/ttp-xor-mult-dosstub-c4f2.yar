rule TTP_XOR_MULT_DOSStub_c4f2 {
  strings:
    $key_c4f2 = { 90 9a [2] e4 82 [2] a3 80 [2] e4 91 [2] aa 9d [2] a6 97 [2] b1 9c [2] aa d2 [2] 97 }

  condition:
    any of them
}