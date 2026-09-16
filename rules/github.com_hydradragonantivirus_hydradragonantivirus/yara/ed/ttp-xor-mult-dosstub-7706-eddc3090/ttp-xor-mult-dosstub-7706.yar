rule TTP_XOR_MULT_DOSStub_7706 {
  strings:
    $key_7706 = { 23 6e [2] 57 76 [2] 10 74 [2] 57 65 [2] 19 69 [2] 15 63 [2] 02 68 [2] 19 26 [2] 24 }

  condition:
    any of them
}