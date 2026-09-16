rule TTP_XOR_MULT_DOSStub_3b17 {
  strings:
    $key_3b17 = { 6f 7f [2] 1b 67 [2] 5c 65 [2] 1b 74 [2] 55 78 [2] 59 72 [2] 4e 79 [2] 55 37 [2] 68 }

  condition:
    any of them
}