rule TTP_XOR_MULT_DOSStub_cbe6 {
  strings:
    $key_cbe6 = { 9f 8e [2] eb 96 [2] ac 94 [2] eb 85 [2] a5 89 [2] a9 83 [2] be 88 [2] a5 c6 [2] 98 }

  condition:
    any of them
}