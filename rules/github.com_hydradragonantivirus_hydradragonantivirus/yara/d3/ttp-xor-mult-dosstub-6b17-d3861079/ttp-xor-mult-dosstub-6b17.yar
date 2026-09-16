rule TTP_XOR_MULT_DOSStub_6b17 {
  strings:
    $key_6b17 = { 3f 7f [2] 4b 67 [2] 0c 65 [2] 4b 74 [2] 05 78 [2] 09 72 [2] 1e 79 [2] 05 37 [2] 38 }

  condition:
    any of them
}