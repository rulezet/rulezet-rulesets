rule TTP_XOR_MULT_DOSStub_edc1 {
  strings:
    $key_edc1 = { b9 a9 [2] cd b1 [2] 8a b3 [2] cd a2 [2] 83 ae [2] 8f a4 [2] 98 af [2] 83 e1 [2] be }

  condition:
    any of them
}