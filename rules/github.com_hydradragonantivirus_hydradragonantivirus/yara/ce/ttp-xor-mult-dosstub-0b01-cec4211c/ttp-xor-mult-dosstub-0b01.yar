rule TTP_XOR_MULT_DOSStub_0b01 {
  strings:
    $key_0b01 = { 5f 69 [2] 2b 71 [2] 6c 73 [2] 2b 62 [2] 65 6e [2] 69 64 [2] 7e 6f [2] 65 21 [2] 58 }

  condition:
    any of them
}