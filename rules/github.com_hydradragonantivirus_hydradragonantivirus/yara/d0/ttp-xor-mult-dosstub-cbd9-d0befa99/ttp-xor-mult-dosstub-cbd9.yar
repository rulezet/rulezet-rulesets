rule TTP_XOR_MULT_DOSStub_cbd9 {
  strings:
    $key_cbd9 = { 9f b1 [2] eb a9 [2] ac ab [2] eb ba [2] a5 b6 [2] a9 bc [2] be b7 [2] a5 f9 [2] 98 }

  condition:
    any of them
}