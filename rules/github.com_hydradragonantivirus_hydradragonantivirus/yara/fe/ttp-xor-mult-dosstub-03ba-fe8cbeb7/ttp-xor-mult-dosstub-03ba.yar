rule TTP_XOR_MULT_DOSStub_03ba {
  strings:
    $key_03ba = { 57 d2 [2] 23 ca [2] 64 c8 [2] 23 d9 [2] 6d d5 [2] 61 df [2] 76 d4 [2] 6d 9a [2] 50 }

  condition:
    any of them
}