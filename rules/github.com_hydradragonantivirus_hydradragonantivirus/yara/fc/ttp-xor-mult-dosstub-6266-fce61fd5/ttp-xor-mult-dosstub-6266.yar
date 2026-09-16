rule TTP_XOR_MULT_DOSStub_6266 {
  strings:
    $key_6266 = { 36 0e [2] 42 16 [2] 05 14 [2] 42 05 [2] 0c 09 [2] 00 03 [2] 17 08 [2] 0c 46 [2] 31 }

  condition:
    any of them
}