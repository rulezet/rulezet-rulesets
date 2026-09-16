rule TTP_XOR_MULT_DOSStub_6506 {
  strings:
    $key_6506 = { 31 6e [2] 45 76 [2] 02 74 [2] 45 65 [2] 0b 69 [2] 07 63 [2] 10 68 [2] 0b 26 [2] 36 }

  condition:
    any of them
}