rule TTP_XOR_MULT_DOSStub_edd9 {
  strings:
    $key_edd9 = { b9 b1 [2] cd a9 [2] 8a ab [2] cd ba [2] 83 b6 [2] 8f bc [2] 98 b7 [2] 83 f9 [2] be }

  condition:
    any of them
}