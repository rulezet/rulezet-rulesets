rule TTP_XOR_MULT_DOSStub_cb5b {
  strings:
    $key_cb5b = { 9f 33 [2] eb 2b [2] ac 29 [2] eb 38 [2] a5 34 [2] a9 3e [2] be 35 [2] a5 7b [2] 98 }

  condition:
    any of them
}