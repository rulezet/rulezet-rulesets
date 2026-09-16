rule TTP_XOR_MULT_DOSStub_cbc5 {
  strings:
    $key_cbc5 = { 9f ad [2] eb b5 [2] ac b7 [2] eb a6 [2] a5 aa [2] a9 a0 [2] be ab [2] a5 e5 [2] 98 }

  condition:
    any of them
}