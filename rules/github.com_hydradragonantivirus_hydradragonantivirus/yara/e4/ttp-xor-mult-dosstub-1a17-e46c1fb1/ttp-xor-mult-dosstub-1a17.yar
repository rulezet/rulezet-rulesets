rule TTP_XOR_MULT_DOSStub_1a17 {
  strings:
    $key_1a17 = { 4e 7f [2] 3a 67 [2] 7d 65 [2] 3a 74 [2] 74 78 [2] 78 72 [2] 6f 79 [2] 74 37 [2] 49 }

  condition:
    any of them
}