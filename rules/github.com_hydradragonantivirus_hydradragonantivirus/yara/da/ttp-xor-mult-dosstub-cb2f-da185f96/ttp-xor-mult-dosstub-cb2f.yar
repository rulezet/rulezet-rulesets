rule TTP_XOR_MULT_DOSStub_cb2f {
  strings:
    $key_cb2f = { 9f 47 [2] eb 5f [2] ac 5d [2] eb 4c [2] a5 40 [2] a9 4a [2] be 41 [2] a5 0f [2] 98 }

  condition:
    any of them
}