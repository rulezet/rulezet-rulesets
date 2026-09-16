rule TTP_XOR_MULT_DOSStub_cbeb {
  strings:
    $key_cbeb = { 9f 83 [2] eb 9b [2] ac 99 [2] eb 88 [2] a5 84 [2] a9 8e [2] be 85 [2] a5 cb [2] 98 }

  condition:
    any of them
}