rule TTP_XOR_MULT_DOSStub_6360 {
  strings:
    $key_6360 = { 37 08 [2] 43 10 [2] 04 12 [2] 43 03 [2] 0d 0f [2] 01 05 [2] 16 0e [2] 0d 40 [2] 30 }

  condition:
    any of them
}