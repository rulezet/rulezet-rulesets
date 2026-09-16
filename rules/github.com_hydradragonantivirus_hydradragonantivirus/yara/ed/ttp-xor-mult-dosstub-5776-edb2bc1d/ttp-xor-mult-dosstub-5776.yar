rule TTP_XOR_MULT_DOSStub_5776 {
  strings:
    $key_5776 = { 03 1e [2] 77 06 [2] 30 04 [2] 77 15 [2] 39 19 [2] 35 13 [2] 22 18 [2] 39 56 [2] 04 }

  condition:
    any of them
}