rule TTP_XOR_MULT_DOSStub_cbf1 {
  strings:
    $key_cbf1 = { 9f 99 [2] eb 81 [2] ac 83 [2] eb 92 [2] a5 9e [2] a9 94 [2] be 9f [2] a5 d1 [2] 98 }

  condition:
    any of them
}