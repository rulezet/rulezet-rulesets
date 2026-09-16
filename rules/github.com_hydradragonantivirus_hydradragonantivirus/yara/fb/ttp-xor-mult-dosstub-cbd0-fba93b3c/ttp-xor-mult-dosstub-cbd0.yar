rule TTP_XOR_MULT_DOSStub_cbd0 {
  strings:
    $key_cbd0 = { 9f b8 [2] eb a0 [2] ac a2 [2] eb b3 [2] a5 bf [2] a9 b5 [2] be be [2] a5 f0 [2] 98 }

  condition:
    any of them
}