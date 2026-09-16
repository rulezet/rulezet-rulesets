rule TTP_XOR_MULT_DOSStub_faef {
  strings:
    $key_faef = { ae 87 [2] da 9f [2] 9d 9d [2] da 8c [2] 94 80 [2] 98 8a [2] 8f 81 [2] 94 cf [2] a9 }

  condition:
    any of them
}