rule TTP_XOR_MULT_DOSStub_14f1 {
  strings:
    $key_14f1 = { 40 99 [2] 34 81 [2] 73 83 [2] 34 92 [2] 7a 9e [2] 76 94 [2] 61 9f [2] 7a d1 [2] 47 }

  condition:
    any of them
}