rule TTP_XOR_MULT_DOSStub_cb8d {
  strings:
    $key_cb8d = { 9f e5 [2] eb fd [2] ac ff [2] eb ee [2] a5 e2 [2] a9 e8 [2] be e3 [2] a5 ad [2] 98 }

  condition:
    any of them
}