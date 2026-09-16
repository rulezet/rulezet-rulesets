rule TTP_XOR_MULT_DOSStub_edba {
  strings:
    $key_edba = { b9 d2 [2] cd ca [2] 8a c8 [2] cd d9 [2] 83 d5 [2] 8f df [2] 98 d4 [2] 83 9a [2] be }

  condition:
    any of them
}