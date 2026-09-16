rule TTP_XOR_MULT_DOSStub_cb6d {
  strings:
    $key_cb6d = { 9f 05 [2] eb 1d [2] ac 1f [2] eb 0e [2] a5 02 [2] a9 08 [2] be 03 [2] a5 4d [2] 98 }

  condition:
    any of them
}