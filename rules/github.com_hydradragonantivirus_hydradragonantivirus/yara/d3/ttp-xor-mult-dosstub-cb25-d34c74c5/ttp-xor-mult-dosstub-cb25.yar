rule TTP_XOR_MULT_DOSStub_cb25 {
  strings:
    $key_cb25 = { 9f 4d [2] eb 55 [2] ac 57 [2] eb 46 [2] a5 4a [2] a9 40 [2] be 4b [2] a5 05 [2] 98 }

  condition:
    any of them
}