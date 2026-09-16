rule TTP_XOR_MULT_DOSStub_6f41 {
  strings:
    $key_6f41 = { 3b 29 [2] 4f 31 [2] 08 33 [2] 4f 22 [2] 01 2e [2] 0d 24 [2] 1a 2f [2] 01 61 [2] 3c }

  condition:
    any of them
}