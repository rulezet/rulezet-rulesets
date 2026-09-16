rule TTP_XOR_MULT_DOSStub_edc0 {
  strings:
    $key_edc0 = { b9 a8 [2] cd b0 [2] 8a b2 [2] cd a3 [2] 83 af [2] 8f a5 [2] 98 ae [2] 83 e0 [2] be }

  condition:
    any of them
}