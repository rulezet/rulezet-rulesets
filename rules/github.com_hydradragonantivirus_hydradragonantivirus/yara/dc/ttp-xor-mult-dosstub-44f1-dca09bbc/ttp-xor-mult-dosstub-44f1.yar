rule TTP_XOR_MULT_DOSStub_44f1 {
  strings:
    $key_44f1 = { 10 99 [2] 64 81 [2] 23 83 [2] 64 92 [2] 2a 9e [2] 26 94 [2] 31 9f [2] 2a d1 [2] 17 }

  condition:
    any of them
}