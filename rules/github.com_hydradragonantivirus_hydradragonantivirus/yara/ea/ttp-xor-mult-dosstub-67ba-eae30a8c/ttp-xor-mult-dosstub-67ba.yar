rule TTP_XOR_MULT_DOSStub_67ba {
  strings:
    $key_67ba = { 33 d2 [2] 47 ca [2] 00 c8 [2] 47 d9 [2] 09 d5 [2] 05 df [2] 12 d4 [2] 09 9a [2] 34 }

  condition:
    any of them
}