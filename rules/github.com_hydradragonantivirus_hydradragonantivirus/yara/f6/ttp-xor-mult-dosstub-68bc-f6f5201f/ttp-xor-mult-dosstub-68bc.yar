rule TTP_XOR_MULT_DOSStub_68bc {
  strings:
    $key_68bc = { 3c d4 [2] 48 cc [2] 0f ce [2] 48 df [2] 06 d3 [2] 0a d9 [2] 1d d2 [2] 06 9c [2] 3b }

  condition:
    any of them
}