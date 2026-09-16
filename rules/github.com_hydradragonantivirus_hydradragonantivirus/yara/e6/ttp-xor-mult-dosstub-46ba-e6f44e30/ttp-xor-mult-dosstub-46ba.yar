rule TTP_XOR_MULT_DOSStub_46ba {
  strings:
    $key_46ba = { 12 d2 [2] 66 ca [2] 21 c8 [2] 66 d9 [2] 28 d5 [2] 24 df [2] 33 d4 [2] 28 9a [2] 15 }

  condition:
    any of them
}