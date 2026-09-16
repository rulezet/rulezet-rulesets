rule TTP_XOR_MULT_DOSStub_cb0b {
  strings:
    $key_cb0b = { 9f 63 [2] eb 7b [2] ac 79 [2] eb 68 [2] a5 64 [2] a9 6e [2] be 65 [2] a5 2b [2] 98 }

  condition:
    any of them
}