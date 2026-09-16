rule TTP_XOR_MULT_DOSStub_0b00 {
  strings:
    $key_0b00 = { 5f 68 [2] 2b 70 [2] 6c 72 [2] 2b 63 [2] 65 6f [2] 69 65 [2] 7e 6e [2] 65 20 [2] 58 }

  condition:
    any of them
}