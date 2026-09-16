rule TTP_XOR_MULT_DOSStub_cbca {
  strings:
    $key_cbca = { 9f a2 [2] eb ba [2] ac b8 [2] eb a9 [2] a5 a5 [2] a9 af [2] be a4 [2] a5 ea [2] 98 }

  condition:
    any of them
}