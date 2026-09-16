rule TTP_XOR_MULT_DOSStub_0b66 {
  strings:
    $key_0b66 = { 5f 0e [2] 2b 16 [2] 6c 14 [2] 2b 05 [2] 65 09 [2] 69 03 [2] 7e 08 [2] 65 46 [2] 58 }

  condition:
    any of them
}