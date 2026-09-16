rule TTP_XOR_MULT_DOSStub_c9ba {
  strings:
    $key_c9ba = { 9d d2 [2] e9 ca [2] ae c8 [2] e9 d9 [2] a7 d5 [2] ab df [2] bc d4 [2] a7 9a [2] 9a }

  condition:
    any of them
}