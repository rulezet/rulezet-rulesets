rule TTP_XOR_MULT_DOSStub_7917 {
  strings:
    $key_7917 = { 2d 7f [2] 59 67 [2] 1e 65 [2] 59 74 [2] 17 78 [2] 1b 72 [2] 0c 79 [2] 17 37 [2] 2a }

  condition:
    any of them
}