rule TTP_XOR_MULT_DOSStub_b9bc {
  strings:
    $key_b9bc = { ed d4 [2] 99 cc [2] de ce [2] 99 df [2] d7 d3 [2] db d9 [2] cc d2 [2] d7 9c [2] ea }

  condition:
    any of them
}