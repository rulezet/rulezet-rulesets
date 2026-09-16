rule TTP_XOR_MULT_DOSStub_57cb {
  strings:
    $key_57cb = { 03 a3 [2] 77 bb [2] 30 b9 [2] 77 a8 [2] 39 a4 [2] 35 ae [2] 22 a5 [2] 39 eb [2] 04 }

  condition:
    any of them
}