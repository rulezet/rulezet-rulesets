rule TTP_XOR_MULT_DOSStub_cb67 {
  strings:
    $key_cb67 = { 9f 0f [2] eb 17 [2] ac 15 [2] eb 04 [2] a5 08 [2] a9 02 [2] be 09 [2] a5 47 [2] 98 }

  condition:
    any of them
}