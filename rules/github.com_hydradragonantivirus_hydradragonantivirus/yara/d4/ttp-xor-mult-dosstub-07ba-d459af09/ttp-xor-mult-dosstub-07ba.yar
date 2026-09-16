rule TTP_XOR_MULT_DOSStub_07ba {
  strings:
    $key_07ba = { 53 d2 [2] 27 ca [2] 60 c8 [2] 27 d9 [2] 69 d5 [2] 65 df [2] 72 d4 [2] 69 9a [2] 54 }

  condition:
    any of them
}