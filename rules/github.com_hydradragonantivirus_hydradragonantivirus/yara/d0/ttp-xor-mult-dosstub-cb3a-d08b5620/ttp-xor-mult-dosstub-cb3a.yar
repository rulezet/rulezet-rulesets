rule TTP_XOR_MULT_DOSStub_cb3a {
  strings:
    $key_cb3a = { 9f 52 [2] eb 4a [2] ac 48 [2] eb 59 [2] a5 55 [2] a9 5f [2] be 54 [2] a5 1a [2] 98 }

  condition:
    any of them
}