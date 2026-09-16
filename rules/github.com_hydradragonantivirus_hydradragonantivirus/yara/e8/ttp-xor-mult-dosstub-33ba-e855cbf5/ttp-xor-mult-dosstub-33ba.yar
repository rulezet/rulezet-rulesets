rule TTP_XOR_MULT_DOSStub_33ba {
  strings:
    $key_33ba = { 67 d2 [2] 13 ca [2] 54 c8 [2] 13 d9 [2] 5d d5 [2] 51 df [2] 46 d4 [2] 5d 9a [2] 60 }

  condition:
    any of them
}