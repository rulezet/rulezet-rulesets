rule TTP_XOR_MULT_DOSStub_7306 {
  strings:
    $key_7306 = { 27 6e [2] 53 76 [2] 14 74 [2] 53 65 [2] 1d 69 [2] 11 63 [2] 06 68 [2] 1d 26 [2] 20 }

  condition:
    any of them
}