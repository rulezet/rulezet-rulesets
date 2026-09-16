rule TTP_XOR_MULT_DOSStub_2b17 {
  strings:
    $key_2b17 = { 7f 7f [2] 0b 67 [2] 4c 65 [2] 0b 74 [2] 45 78 [2] 49 72 [2] 5e 79 [2] 45 37 [2] 78 }

  condition:
    any of them
}