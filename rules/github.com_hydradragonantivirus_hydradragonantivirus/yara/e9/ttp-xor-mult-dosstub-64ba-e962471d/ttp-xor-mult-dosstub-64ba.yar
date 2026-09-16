rule TTP_XOR_MULT_DOSStub_64ba {
  strings:
    $key_64ba = { 30 d2 [2] 44 ca [2] 03 c8 [2] 44 d9 [2] 0a d5 [2] 06 df [2] 11 d4 [2] 0a 9a [2] 37 }

  condition:
    any of them
}