rule TTP_XOR_MULT_DOSStub_28bc {
  strings:
    $key_28bc = { 7c d4 [2] 08 cc [2] 4f ce [2] 08 df [2] 46 d3 [2] 4a d9 [2] 5d d2 [2] 46 9c [2] 7b }

  condition:
    any of them
}