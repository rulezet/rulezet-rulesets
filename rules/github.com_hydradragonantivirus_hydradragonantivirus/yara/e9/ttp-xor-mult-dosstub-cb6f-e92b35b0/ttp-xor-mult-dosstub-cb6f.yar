rule TTP_XOR_MULT_DOSStub_cb6f {
  strings:
    $key_cb6f = { 9f 07 [2] eb 1f [2] ac 1d [2] eb 0c [2] a5 00 [2] a9 0a [2] be 01 [2] a5 4f [2] 98 }

  condition:
    any of them
}