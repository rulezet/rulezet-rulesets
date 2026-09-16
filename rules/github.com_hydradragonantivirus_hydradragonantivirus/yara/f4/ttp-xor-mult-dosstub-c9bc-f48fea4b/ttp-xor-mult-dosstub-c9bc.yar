rule TTP_XOR_MULT_DOSStub_c9bc {
  strings:
    $key_c9bc = { 9d d4 [2] e9 cc [2] ae ce [2] e9 df [2] a7 d3 [2] ab d9 [2] bc d2 [2] a7 9c [2] 9a }

  condition:
    any of them
}