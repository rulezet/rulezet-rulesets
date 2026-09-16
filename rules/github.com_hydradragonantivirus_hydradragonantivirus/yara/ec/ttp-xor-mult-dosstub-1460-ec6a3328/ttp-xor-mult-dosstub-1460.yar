rule TTP_XOR_MULT_DOSStub_1460 {
  strings:
    $key_1460 = { 40 08 [2] 34 10 [2] 73 12 [2] 34 03 [2] 7a 0f [2] 76 05 [2] 61 0e [2] 7a 40 [2] 47 }

  condition:
    any of them
}