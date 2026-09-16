rule TTP_XOR_MULT_DOSStub_1e17 {
  strings:
    $key_1e17 = { 4a 7f [2] 3e 67 [2] 79 65 [2] 3e 74 [2] 70 78 [2] 7c 72 [2] 6b 79 [2] 70 37 [2] 4d }

  condition:
    any of them
}