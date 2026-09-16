rule TTP_XOR_MULT_DOSStub_1b27 {
  strings:
    $key_1b27 = { 4f 4f [2] 3b 57 [2] 7c 55 [2] 3b 44 [2] 75 48 [2] 79 42 [2] 6e 49 [2] 75 07 [2] 48 }

  condition:
    any of them
}