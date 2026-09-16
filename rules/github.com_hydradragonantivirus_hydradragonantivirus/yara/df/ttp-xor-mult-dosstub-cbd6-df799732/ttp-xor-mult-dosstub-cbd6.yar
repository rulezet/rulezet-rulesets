rule TTP_XOR_MULT_DOSStub_cbd6 {
  strings:
    $key_cbd6 = { 9f be [2] eb a6 [2] ac a4 [2] eb b5 [2] a5 b9 [2] a9 b3 [2] be b8 [2] a5 f6 [2] 98 }

  condition:
    any of them
}