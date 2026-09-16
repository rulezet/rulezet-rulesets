rule TTP_XOR_MULT_DOSStub_2af1 {
  strings:
    $key_2af1 = { 7e 99 [2] 0a 81 [2] 4d 83 [2] 0a 92 [2] 44 9e [2] 48 94 [2] 5f 9f [2] 44 d1 [2] 79 }

  condition:
    any of them
}