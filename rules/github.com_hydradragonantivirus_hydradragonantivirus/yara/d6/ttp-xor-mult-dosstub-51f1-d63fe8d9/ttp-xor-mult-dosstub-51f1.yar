rule TTP_XOR_MULT_DOSStub_51f1 {
  strings:
    $key_51f1 = { 05 99 [2] 71 81 [2] 36 83 [2] 71 92 [2] 3f 9e [2] 33 94 [2] 24 9f [2] 3f d1 [2] 02 }

  condition:
    any of them
}