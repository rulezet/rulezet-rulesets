rule TTP_XOR_MULT_DOSStub_cb20 {
  strings:
    $key_cb20 = { 9f 48 [2] eb 50 [2] ac 52 [2] eb 43 [2] a5 4f [2] a9 45 [2] be 4e [2] a5 00 [2] 98 }

  condition:
    any of them
}