rule TTP_XOR_MULT_DOSStub_4f60 {
  strings:
    $key_4f60 = { 1b 08 [2] 6f 10 [2] 28 12 [2] 6f 03 [2] 21 0f [2] 2d 05 [2] 3a 0e [2] 21 40 [2] 1c }

  condition:
    any of them
}