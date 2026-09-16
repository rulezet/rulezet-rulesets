rule TTP_XOR_MULT_DOSStub_1160 {
  strings:
    $key_1160 = { 45 08 [2] 31 10 [2] 76 12 [2] 31 03 [2] 7f 0f [2] 73 05 [2] 64 0e [2] 7f 40 [2] 42 }

  condition:
    any of them
}