rule TTP_XOR_MULT_DOSStub_4b17 {
  strings:
    $key_4b17 = { 1f 7f [2] 6b 67 [2] 2c 65 [2] 6b 74 [2] 25 78 [2] 29 72 [2] 3e 79 [2] 25 37 [2] 18 }

  condition:
    any of them
}