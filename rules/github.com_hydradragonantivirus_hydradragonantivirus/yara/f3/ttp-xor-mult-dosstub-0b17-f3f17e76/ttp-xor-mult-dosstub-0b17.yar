rule TTP_XOR_MULT_DOSStub_0b17 {
  strings:
    $key_0b17 = { 5f 7f [2] 2b 67 [2] 6c 65 [2] 2b 74 [2] 65 78 [2] 69 72 [2] 7e 79 [2] 65 37 [2] 58 }

  condition:
    any of them
}