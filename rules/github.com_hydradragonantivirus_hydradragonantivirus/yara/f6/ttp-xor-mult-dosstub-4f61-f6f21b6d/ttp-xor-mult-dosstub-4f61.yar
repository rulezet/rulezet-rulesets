rule TTP_XOR_MULT_DOSStub_4f61 {
  strings:
    $key_4f61 = { 1b 09 [2] 6f 11 [2] 28 13 [2] 6f 02 [2] 21 0e [2] 2d 04 [2] 3a 0f [2] 21 41 [2] 1c }

  condition:
    any of them
}