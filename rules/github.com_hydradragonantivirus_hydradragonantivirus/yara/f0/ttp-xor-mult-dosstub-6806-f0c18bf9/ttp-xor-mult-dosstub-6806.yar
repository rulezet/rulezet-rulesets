rule TTP_XOR_MULT_DOSStub_6806 {
  strings:
    $key_6806 = { 3c 6e [2] 48 76 [2] 0f 74 [2] 48 65 [2] 06 69 [2] 0a 63 [2] 1d 68 [2] 06 26 [2] 3b }

  condition:
    any of them
}