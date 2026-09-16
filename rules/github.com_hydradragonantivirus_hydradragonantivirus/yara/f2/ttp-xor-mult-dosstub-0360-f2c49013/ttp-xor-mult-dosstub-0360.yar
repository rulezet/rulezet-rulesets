rule TTP_XOR_MULT_DOSStub_0360 {
  strings:
    $key_0360 = { 57 08 [2] 23 10 [2] 64 12 [2] 23 03 [2] 6d 0f [2] 61 05 [2] 76 0e [2] 6d 40 [2] 50 }

  condition:
    any of them
}