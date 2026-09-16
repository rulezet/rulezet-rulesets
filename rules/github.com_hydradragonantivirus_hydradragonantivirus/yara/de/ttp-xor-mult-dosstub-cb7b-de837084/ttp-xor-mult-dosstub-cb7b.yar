rule TTP_XOR_MULT_DOSStub_cb7b {
  strings:
    $key_cb7b = { 9f 13 [2] eb 0b [2] ac 09 [2] eb 18 [2] a5 14 [2] a9 1e [2] be 15 [2] a5 5b [2] 98 }

  condition:
    any of them
}