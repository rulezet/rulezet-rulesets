rule TTP_XOR_MULT_DOSStub_6f06 {
  strings:
    $key_6f06 = { 3b 6e [2] 4f 76 [2] 08 74 [2] 4f 65 [2] 01 69 [2] 0d 63 [2] 1a 68 [2] 01 26 [2] 3c }

  condition:
    any of them
}