rule TTP_XOR_MULT_DOSStub_f8bc {
  strings:
    $key_f8bc = { ac d4 [2] d8 cc [2] 9f ce [2] d8 df [2] 96 d3 [2] 9a d9 [2] 8d d2 [2] 96 9c [2] ab }

  condition:
    any of them
}