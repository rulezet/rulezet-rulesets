rule TTP_XOR_MULT_DOSStub_cb95 {
  strings:
    $key_cb95 = { 9f fd [2] eb e5 [2] ac e7 [2] eb f6 [2] a5 fa [2] a9 f0 [2] be fb [2] a5 b5 [2] 98 }

  condition:
    any of them
}