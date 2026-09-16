rule TTP_XOR_MULT_DOSStub_48ba {
  strings:
    $key_48ba = { 1c d2 [2] 68 ca [2] 2f c8 [2] 68 d9 [2] 26 d5 [2] 2a df [2] 3d d4 [2] 26 9a [2] 1b }

  condition:
    any of them
}