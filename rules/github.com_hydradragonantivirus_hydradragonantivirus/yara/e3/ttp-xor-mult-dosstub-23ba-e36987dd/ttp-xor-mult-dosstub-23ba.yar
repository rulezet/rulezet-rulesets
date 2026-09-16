rule TTP_XOR_MULT_DOSStub_23ba {
  strings:
    $key_23ba = { 77 d2 [2] 03 ca [2] 44 c8 [2] 03 d9 [2] 4d d5 [2] 41 df [2] 56 d4 [2] 4d 9a [2] 70 }

  condition:
    any of them
}