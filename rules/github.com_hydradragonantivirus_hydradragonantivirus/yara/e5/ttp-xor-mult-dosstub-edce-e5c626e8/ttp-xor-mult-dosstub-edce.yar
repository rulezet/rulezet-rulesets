rule TTP_XOR_MULT_DOSStub_edce {
  strings:
    $key_edce = { b9 a6 [2] cd be [2] 8a bc [2] cd ad [2] 83 a1 [2] 8f ab [2] 98 a0 [2] 83 ee [2] be }

  condition:
    any of them
}