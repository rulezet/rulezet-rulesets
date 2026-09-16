rule TTP_XOR_MULT_DOSStub_cb4a {
  strings:
    $key_cb4a = { 9f 22 [2] eb 3a [2] ac 38 [2] eb 29 [2] a5 25 [2] a9 2f [2] be 24 [2] a5 6a [2] 98 }

  condition:
    any of them
}