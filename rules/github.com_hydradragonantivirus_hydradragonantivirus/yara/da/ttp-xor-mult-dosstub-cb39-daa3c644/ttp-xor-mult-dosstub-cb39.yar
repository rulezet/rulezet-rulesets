rule TTP_XOR_MULT_DOSStub_cb39 {
  strings:
    $key_cb39 = { 9f 51 [2] eb 49 [2] ac 4b [2] eb 5a [2] a5 56 [2] a9 5c [2] be 57 [2] a5 19 [2] 98 }

  condition:
    any of them
}