rule TTP_XOR_MULT_DOSStub_cb65 {
  strings:
    $key_cb65 = { 9f 0d [2] eb 15 [2] ac 17 [2] eb 06 [2] a5 0a [2] a9 00 [2] be 0b [2] a5 45 [2] 98 }

  condition:
    any of them
}