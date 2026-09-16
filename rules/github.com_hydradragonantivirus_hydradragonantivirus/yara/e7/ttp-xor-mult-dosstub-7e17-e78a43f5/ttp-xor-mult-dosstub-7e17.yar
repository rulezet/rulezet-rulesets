rule TTP_XOR_MULT_DOSStub_7e17 {
  strings:
    $key_7e17 = { 2a 7f [2] 5e 67 [2] 19 65 [2] 5e 74 [2] 10 78 [2] 1c 72 [2] 0b 79 [2] 10 37 [2] 2d }

  condition:
    any of them
}