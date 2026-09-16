rule TTP_XOR_MULT_DOSStub_cb86 {
  strings:
    $key_cb86 = { 9f ee [2] eb f6 [2] ac f4 [2] eb e5 [2] a5 e9 [2] a9 e3 [2] be e8 [2] a5 a6 [2] 98 }

  condition:
    any of them
}