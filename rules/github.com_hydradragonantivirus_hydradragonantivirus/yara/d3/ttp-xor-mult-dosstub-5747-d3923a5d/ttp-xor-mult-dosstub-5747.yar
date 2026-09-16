rule TTP_XOR_MULT_DOSStub_5747 {
  strings:
    $key_5747 = { 03 2f [2] 77 37 [2] 30 35 [2] 77 24 [2] 39 28 [2] 35 22 [2] 22 29 [2] 39 67 [2] 04 }

  condition:
    any of them
}