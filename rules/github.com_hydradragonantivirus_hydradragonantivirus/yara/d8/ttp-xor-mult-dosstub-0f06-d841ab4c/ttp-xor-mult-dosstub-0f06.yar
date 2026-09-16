rule TTP_XOR_MULT_DOSStub_0f06 {
  strings:
    $key_0f06 = { 5b 6e [2] 2f 76 [2] 68 74 [2] 2f 65 [2] 61 69 [2] 6d 63 [2] 7a 68 [2] 61 26 [2] 5c }

  condition:
    any of them
}