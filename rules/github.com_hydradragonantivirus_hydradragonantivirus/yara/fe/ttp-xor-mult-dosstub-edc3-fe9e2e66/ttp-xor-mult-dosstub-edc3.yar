rule TTP_XOR_MULT_DOSStub_edc3 {
  strings:
    $key_edc3 = { b9 ab [2] cd b3 [2] 8a b1 [2] cd a0 [2] 83 ac [2] 8f a6 [2] 98 ad [2] 83 e3 [2] be }

  condition:
    any of them
}