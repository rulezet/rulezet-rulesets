rule TTP_XOR_MULT_DOSStub_2b06 {
  strings:
    $key_2b06 = { 7f 6e [2] 0b 76 [2] 4c 74 [2] 0b 65 [2] 45 69 [2] 49 63 [2] 5e 68 [2] 45 26 [2] 78 }

  condition:
    any of them
}