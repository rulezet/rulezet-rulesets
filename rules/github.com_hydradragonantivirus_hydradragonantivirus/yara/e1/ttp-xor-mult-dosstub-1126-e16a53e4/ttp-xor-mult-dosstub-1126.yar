rule TTP_XOR_MULT_DOSStub_1126 {
  strings:
    $key_1126 = { 45 4e [2] 31 56 [2] 76 54 [2] 31 45 [2] 7f 49 [2] 73 43 [2] 64 48 [2] 7f 06 [2] 42 }

  condition:
    any of them
}