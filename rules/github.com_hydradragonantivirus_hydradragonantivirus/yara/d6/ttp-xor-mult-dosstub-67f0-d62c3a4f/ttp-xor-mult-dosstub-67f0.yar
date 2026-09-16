rule TTP_XOR_MULT_DOSStub_67f0 {
  strings:
    $key_67f0 = { 33 98 [2] 47 80 [2] 00 82 [2] 47 93 [2] 09 9f [2] 05 95 [2] 12 9e [2] 09 d0 [2] 34 }

  condition:
    any of them
}