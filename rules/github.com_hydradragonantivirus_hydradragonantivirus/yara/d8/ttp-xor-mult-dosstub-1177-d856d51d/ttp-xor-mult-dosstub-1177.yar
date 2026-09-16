rule TTP_XOR_MULT_DOSStub_1177 {
  strings:
    $key_1177 = { 45 1f [2] 31 07 [2] 76 05 [2] 31 14 [2] 7f 18 [2] 73 12 [2] 64 19 [2] 7f 57 [2] 42 }

  condition:
    any of them
}