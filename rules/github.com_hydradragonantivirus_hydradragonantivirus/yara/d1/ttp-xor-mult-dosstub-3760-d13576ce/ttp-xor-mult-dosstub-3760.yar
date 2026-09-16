rule TTP_XOR_MULT_DOSStub_3760 {
  strings:
    $key_3760 = { 63 08 [2] 17 10 [2] 50 12 [2] 17 03 [2] 59 0f [2] 55 05 [2] 42 0e [2] 59 40 [2] 64 }

  condition:
    any of them
}