rule TTP_XOR_MULT_DOSStub_6f01 {
  strings:
    $key_6f01 = { 3b 69 [2] 4f 71 [2] 08 73 [2] 4f 62 [2] 01 6e [2] 0d 64 [2] 1a 6f [2] 01 21 [2] 3c }

  condition:
    any of them
}