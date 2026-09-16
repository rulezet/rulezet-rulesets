rule TTP_XOR_MULT_DOSStub_3271 {
  strings:
    $key_3271 = { 66 19 [2] 12 01 [2] 55 03 [2] 12 12 [2] 5c 1e [2] 50 14 [2] 47 1f [2] 5c 51 [2] 61 }

  condition:
    any of them
}