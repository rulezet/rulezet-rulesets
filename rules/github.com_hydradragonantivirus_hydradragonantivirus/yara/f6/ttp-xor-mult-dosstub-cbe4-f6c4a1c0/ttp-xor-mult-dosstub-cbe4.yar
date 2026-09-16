rule TTP_XOR_MULT_DOSStub_cbe4 {
  strings:
    $key_cbe4 = { 9f 8c [2] eb 94 [2] ac 96 [2] eb 87 [2] a5 8b [2] a9 81 [2] be 8a [2] a5 c4 [2] 98 }

  condition:
    any of them
}