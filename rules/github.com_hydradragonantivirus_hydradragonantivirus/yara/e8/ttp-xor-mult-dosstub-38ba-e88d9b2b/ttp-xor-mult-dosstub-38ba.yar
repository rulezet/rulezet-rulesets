rule TTP_XOR_MULT_DOSStub_38ba {
  strings:
    $key_38ba = { 6c d2 [2] 18 ca [2] 5f c8 [2] 18 d9 [2] 56 d5 [2] 5a df [2] 4d d4 [2] 56 9a [2] 6b }

  condition:
    any of them
}