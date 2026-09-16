rule TTP_XOR_MULT_DOSStub_cb0c {
  strings:
    $key_cb0c = { 9f 64 [2] eb 7c [2] ac 7e [2] eb 6f [2] a5 63 [2] a9 69 [2] be 62 [2] a5 2c [2] 98 }

  condition:
    any of them
}