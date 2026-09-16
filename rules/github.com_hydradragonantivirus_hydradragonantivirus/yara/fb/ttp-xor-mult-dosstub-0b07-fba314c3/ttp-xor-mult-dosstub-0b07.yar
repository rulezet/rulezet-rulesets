rule TTP_XOR_MULT_DOSStub_0b07 {
  strings:
    $key_0b07 = { 5f 6f [2] 2b 77 [2] 6c 75 [2] 2b 64 [2] 65 68 [2] 69 62 [2] 7e 69 [2] 65 27 [2] 58 }

  condition:
    any of them
}