rule TTP_XOR_MULT_DOSStub_cb27 {
  strings:
    $key_cb27 = { 9f 4f [2] eb 57 [2] ac 55 [2] eb 44 [2] a5 48 [2] a9 42 [2] be 49 [2] a5 07 [2] 98 }

  condition:
    any of them
}