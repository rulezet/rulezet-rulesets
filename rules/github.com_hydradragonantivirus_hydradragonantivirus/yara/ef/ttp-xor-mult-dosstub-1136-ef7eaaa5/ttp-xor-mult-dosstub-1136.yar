rule TTP_XOR_MULT_DOSStub_1136 {
  strings:
    $key_1136 = { 45 5e [2] 31 46 [2] 76 44 [2] 31 55 [2] 7f 59 [2] 73 53 [2] 64 58 [2] 7f 16 [2] 42 }

  condition:
    any of them
}