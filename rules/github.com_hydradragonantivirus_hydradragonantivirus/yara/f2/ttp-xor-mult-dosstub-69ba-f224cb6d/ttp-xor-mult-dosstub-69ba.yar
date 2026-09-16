rule TTP_XOR_MULT_DOSStub_69ba {
  strings:
    $key_69ba = { 3d d2 [2] 49 ca [2] 0e c8 [2] 49 d9 [2] 07 d5 [2] 0b df [2] 1c d4 [2] 07 9a [2] 3a }

  condition:
    any of them
}