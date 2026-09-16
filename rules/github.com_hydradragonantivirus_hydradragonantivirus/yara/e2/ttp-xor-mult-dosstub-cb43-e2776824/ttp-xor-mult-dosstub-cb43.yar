rule TTP_XOR_MULT_DOSStub_cb43 {
  strings:
    $key_cb43 = { 9f 2b [2] eb 33 [2] ac 31 [2] eb 20 [2] a5 2c [2] a9 26 [2] be 2d [2] a5 63 [2] 98 }

  condition:
    any of them
}