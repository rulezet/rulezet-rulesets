rule TTP_XOR_MULT_DOSStub_5271 {
  strings:
    $key_5271 = { 06 19 [2] 72 01 [2] 35 03 [2] 72 12 [2] 3c 1e [2] 30 14 [2] 27 1f [2] 3c 51 [2] 01 }

  condition:
    any of them
}