rule TTP_XOR_MULT_DOSStub_3266 {
  strings:
    $key_3266 = { 66 0e [2] 12 16 [2] 55 14 [2] 12 05 [2] 5c 09 [2] 50 03 [2] 47 08 [2] 5c 46 [2] 61 }

  condition:
    any of them
}