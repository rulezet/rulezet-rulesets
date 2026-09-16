rule TTP_XOR_MULT_DOSStub_6596 {
  strings:
    $key_6596 = { 31 fe [2] 45 e6 [2] 02 e4 [2] 45 f5 [2] 0b f9 [2] 07 f3 [2] 10 f8 [2] 0b b6 [2] 36 }

  condition:
    any of them
}