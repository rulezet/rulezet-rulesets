rule TTP_XOR_MULT_DOSStub_cb17 {
  strings:
    $key_cb17 = { 9f 7f [2] eb 67 [2] ac 65 [2] eb 74 [2] a5 78 [2] a9 72 [2] be 79 [2] a5 37 [2] 98 }

  condition:
    any of them
}