rule TTP_XOR_MULT_DOSStub_deba {
  strings:
    $key_deba = { 8a d2 [2] fe ca [2] b9 c8 [2] fe d9 [2] b0 d5 [2] bc df [2] ab d4 [2] b0 9a [2] 8d }

  condition:
    any of them
}