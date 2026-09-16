rule TTP_XOR_MULT_DOSStub_cb9b {
  strings:
    $key_cb9b = { 9f f3 [2] eb eb [2] ac e9 [2] eb f8 [2] a5 f4 [2] a9 fe [2] be f5 [2] a5 bb [2] 98 }

  condition:
    any of them
}