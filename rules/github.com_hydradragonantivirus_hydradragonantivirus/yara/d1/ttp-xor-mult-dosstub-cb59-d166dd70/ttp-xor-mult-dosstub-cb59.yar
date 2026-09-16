rule TTP_XOR_MULT_DOSStub_cb59 {
  strings:
    $key_cb59 = { 9f 31 [2] eb 29 [2] ac 2b [2] eb 3a [2] a5 36 [2] a9 3c [2] be 37 [2] a5 79 [2] 98 }

  condition:
    any of them
}