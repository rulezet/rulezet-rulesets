rule TTP_XOR_MULT_DOSStub_0b61 {
  strings:
    $key_0b61 = { 5f 09 [2] 2b 11 [2] 6c 13 [2] 2b 02 [2] 65 0e [2] 69 04 [2] 7e 0f [2] 65 41 [2] 58 }

  condition:
    any of them
}