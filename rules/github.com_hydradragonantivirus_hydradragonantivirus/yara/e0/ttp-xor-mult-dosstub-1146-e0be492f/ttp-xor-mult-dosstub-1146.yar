rule TTP_XOR_MULT_DOSStub_1146 {
  strings:
    $key_1146 = { 45 2e [2] 31 36 [2] 76 34 [2] 31 25 [2] 7f 29 [2] 73 23 [2] 64 28 [2] 7f 66 [2] 42 }

  condition:
    any of them
}