rule TTP_XOR_MULT_DOSStub_f0bc {
  strings:
    $key_f0bc = { a4 d4 [2] d0 cc [2] 97 ce [2] d0 df [2] 9e d3 [2] 92 d9 [2] 85 d2 [2] 9e 9c [2] a3 }

  condition:
    any of them
}