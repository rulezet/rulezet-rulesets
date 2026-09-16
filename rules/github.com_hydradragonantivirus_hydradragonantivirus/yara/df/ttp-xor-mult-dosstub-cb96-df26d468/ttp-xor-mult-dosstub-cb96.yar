rule TTP_XOR_MULT_DOSStub_cb96 {
  strings:
    $key_cb96 = { 9f fe [2] eb e6 [2] ac e4 [2] eb f5 [2] a5 f9 [2] a9 f3 [2] be f8 [2] a5 b6 [2] 98 }

  condition:
    any of them
}