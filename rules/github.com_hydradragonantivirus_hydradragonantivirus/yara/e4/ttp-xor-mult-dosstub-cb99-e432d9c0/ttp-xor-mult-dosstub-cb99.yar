rule TTP_XOR_MULT_DOSStub_cb99 {
  strings:
    $key_cb99 = { 9f f1 [2] eb e9 [2] ac eb [2] eb fa [2] a5 f6 [2] a9 fc [2] be f7 [2] a5 b9 [2] 98 }

  condition:
    any of them
}