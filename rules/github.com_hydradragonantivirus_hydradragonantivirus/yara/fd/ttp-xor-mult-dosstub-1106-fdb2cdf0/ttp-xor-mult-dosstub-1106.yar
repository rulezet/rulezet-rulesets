rule TTP_XOR_MULT_DOSStub_1106 {
  strings:
    $key_1106 = { 45 6e [2] 31 76 [2] 76 74 [2] 31 65 [2] 7f 69 [2] 73 63 [2] 64 68 [2] 7f 26 [2] 42 }

  condition:
    any of them
}