rule TTP_XOR_MULT_DOSStub_4f67 {
  strings:
    $key_4f67 = { 1b 0f [2] 6f 17 [2] 28 15 [2] 6f 04 [2] 21 08 [2] 2d 02 [2] 3a 09 [2] 21 47 [2] 1c }

  condition:
    any of them
}