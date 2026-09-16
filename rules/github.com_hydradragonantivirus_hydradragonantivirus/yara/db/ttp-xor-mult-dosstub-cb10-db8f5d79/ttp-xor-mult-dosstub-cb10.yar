rule TTP_XOR_MULT_DOSStub_cb10 {
  strings:
    $key_cb10 = { 9f 78 [2] eb 60 [2] ac 62 [2] eb 73 [2] a5 7f [2] a9 75 [2] be 7e [2] a5 30 [2] 98 }

  condition:
    any of them
}