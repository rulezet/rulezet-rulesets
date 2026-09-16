rule TTP_XOR_MULT_DOSStub_7b27 {
  strings:
    $key_7b27 = { 2f 4f [2] 5b 57 [2] 1c 55 [2] 5b 44 [2] 15 48 [2] 19 42 [2] 0e 49 [2] 15 07 [2] 28 }

  condition:
    any of them
}