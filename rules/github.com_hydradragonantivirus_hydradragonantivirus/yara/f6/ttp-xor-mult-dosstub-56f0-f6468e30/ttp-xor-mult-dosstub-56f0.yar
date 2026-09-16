rule TTP_XOR_MULT_DOSStub_56f0 {
  strings:
    $key_56f0 = { 02 98 [2] 76 80 [2] 31 82 [2] 76 93 [2] 38 9f [2] 34 95 [2] 23 9e [2] 38 d0 [2] 05 }

  condition:
    any of them
}