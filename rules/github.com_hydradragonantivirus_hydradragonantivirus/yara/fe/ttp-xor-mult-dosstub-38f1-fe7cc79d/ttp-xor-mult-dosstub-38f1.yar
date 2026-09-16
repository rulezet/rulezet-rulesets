rule TTP_XOR_MULT_DOSStub_38f1 {
  strings:
    $key_38f1 = { 6c 99 [2] 18 81 [2] 5f 83 [2] 18 92 [2] 56 9e [2] 5a 94 [2] 4d 9f [2] 56 d1 [2] 6b }

  condition:
    any of them
}