rule TTP_XOR_MULT_DOSStub_cbef {
  strings:
    $key_cbef = { 9f 87 [2] eb 9f [2] ac 9d [2] eb 8c [2] a5 80 [2] a9 8a [2] be 81 [2] a5 cf [2] 98 }

  condition:
    any of them
}