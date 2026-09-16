rule TTP_XOR_MULT_DOSStub_6b06 {
  strings:
    $key_6b06 = { 3f 6e [2] 4b 76 [2] 0c 74 [2] 4b 65 [2] 05 69 [2] 09 63 [2] 1e 68 [2] 05 26 [2] 38 }

  condition:
    any of them
}