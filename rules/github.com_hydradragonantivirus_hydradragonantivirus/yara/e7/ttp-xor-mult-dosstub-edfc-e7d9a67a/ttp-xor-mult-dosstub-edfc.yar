rule TTP_XOR_MULT_DOSStub_edfc {
  strings:
    $key_edfc = { b9 94 [2] cd 8c [2] 8a 8e [2] cd 9f [2] 83 93 [2] 8f 99 [2] 98 92 [2] 83 dc [2] be }

  condition:
    any of them
}