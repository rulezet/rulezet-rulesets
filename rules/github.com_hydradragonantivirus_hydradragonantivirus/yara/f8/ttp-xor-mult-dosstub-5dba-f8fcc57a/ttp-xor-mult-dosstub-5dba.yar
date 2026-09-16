rule TTP_XOR_MULT_DOSStub_5dba {
  strings:
    $key_5dba = { 09 d2 [2] 7d ca [2] 3a c8 [2] 7d d9 [2] 33 d5 [2] 3f df [2] 28 d4 [2] 33 9a [2] 0e }

  condition:
    any of them
}