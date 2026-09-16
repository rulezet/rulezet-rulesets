rule TTP_XOR_MULT_DOSStub_cb08 {
  strings:
    $key_cb08 = { 9f 60 [2] eb 78 [2] ac 7a [2] eb 6b [2] a5 67 [2] a9 6d [2] be 66 [2] a5 28 [2] 98 }

  condition:
    any of them
}