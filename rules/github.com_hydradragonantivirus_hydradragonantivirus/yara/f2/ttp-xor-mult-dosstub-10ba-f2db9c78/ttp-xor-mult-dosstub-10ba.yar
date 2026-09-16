rule TTP_XOR_MULT_DOSStub_10ba {
  strings:
    $key_10ba = { 44 d2 [2] 30 ca [2] 77 c8 [2] 30 d9 [2] 7e d5 [2] 72 df [2] 65 d4 [2] 7e 9a [2] 43 }

  condition:
    any of them
}