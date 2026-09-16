rule TTP_XOR_MULT_DOSStub_cb26 {
  strings:
    $key_cb26 = { 9f 4e [2] eb 56 [2] ac 54 [2] eb 45 [2] a5 49 [2] a9 43 [2] be 48 [2] a5 06 [2] 98 }

  condition:
    any of them
}