rule TTP_XOR_MULT_DOSStub_cb51 {
  strings:
    $key_cb51 = { 9f 39 [2] eb 21 [2] ac 23 [2] eb 32 [2] a5 3e [2] a9 34 [2] be 3f [2] a5 71 [2] 98 }

  condition:
    any of them
}