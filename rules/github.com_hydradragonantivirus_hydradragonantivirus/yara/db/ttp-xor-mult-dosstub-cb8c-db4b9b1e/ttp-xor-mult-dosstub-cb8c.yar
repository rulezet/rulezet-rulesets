rule TTP_XOR_MULT_DOSStub_cb8c {
  strings:
    $key_cb8c = { 9f e4 [2] eb fc [2] ac fe [2] eb ef [2] a5 e3 [2] a9 e9 [2] be e2 [2] a5 ac [2] 98 }

  condition:
    any of them
}