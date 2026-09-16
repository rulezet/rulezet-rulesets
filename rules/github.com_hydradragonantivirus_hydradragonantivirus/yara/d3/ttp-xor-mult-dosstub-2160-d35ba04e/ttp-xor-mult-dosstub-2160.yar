rule TTP_XOR_MULT_DOSStub_2160 {
  strings:
    $key_2160 = { 75 08 [2] 01 10 [2] 46 12 [2] 01 03 [2] 4f 0f [2] 43 05 [2] 54 0e [2] 4f 40 [2] 72 }

  condition:
    any of them
}