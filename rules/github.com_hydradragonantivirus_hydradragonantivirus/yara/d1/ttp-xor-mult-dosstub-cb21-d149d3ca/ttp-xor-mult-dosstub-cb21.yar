rule TTP_XOR_MULT_DOSStub_cb21 {
  strings:
    $key_cb21 = { 9f 49 [2] eb 51 [2] ac 53 [2] eb 42 [2] a5 4e [2] a9 44 [2] be 4f [2] a5 01 [2] 98 }

  condition:
    any of them
}