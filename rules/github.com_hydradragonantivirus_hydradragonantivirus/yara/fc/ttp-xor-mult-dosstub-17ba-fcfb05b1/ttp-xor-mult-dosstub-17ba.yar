rule TTP_XOR_MULT_DOSStub_17ba {
  strings:
    $key_17ba = { 43 d2 [2] 37 ca [2] 70 c8 [2] 37 d9 [2] 79 d5 [2] 75 df [2] 62 d4 [2] 79 9a [2] 44 }

  condition:
    any of them
}