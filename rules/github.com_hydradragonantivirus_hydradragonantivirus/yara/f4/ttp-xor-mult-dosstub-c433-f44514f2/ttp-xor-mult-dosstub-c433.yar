rule TTP_XOR_MULT_DOSStub_c433 {
  strings:
    $key_c433 = { 90 5b [2] e4 43 [2] a3 41 [2] e4 50 [2] aa 5c [2] a6 56 [2] b1 5d [2] aa 13 [2] 97 }

  condition:
    any of them
}