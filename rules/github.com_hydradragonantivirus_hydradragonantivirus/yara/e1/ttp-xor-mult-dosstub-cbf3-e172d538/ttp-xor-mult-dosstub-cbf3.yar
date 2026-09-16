rule TTP_XOR_MULT_DOSStub_cbf3 {
  strings:
    $key_cbf3 = { 9f 9b [2] eb 83 [2] ac 81 [2] eb 90 [2] a5 9c [2] a9 96 [2] be 9d [2] a5 d3 [2] 98 }

  condition:
    any of them
}