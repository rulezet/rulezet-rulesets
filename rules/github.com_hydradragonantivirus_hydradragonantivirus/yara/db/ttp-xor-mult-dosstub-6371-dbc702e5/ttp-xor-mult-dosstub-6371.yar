rule TTP_XOR_MULT_DOSStub_6371 {
  strings:
    $key_6371 = { 37 19 [2] 43 01 [2] 04 03 [2] 43 12 [2] 0d 1e [2] 01 14 [2] 16 1f [2] 0d 51 [2] 30 }

  condition:
    any of them
}