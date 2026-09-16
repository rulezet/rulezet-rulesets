rule TTP_XOR_MULT_DOSStub_bbef {
  strings:
    $key_bbef = { ef 87 [2] 9b 9f [2] dc 9d [2] 9b 8c [2] d5 80 [2] d9 8a [2] ce 81 [2] d5 cf [2] e8 }

  condition:
    any of them
}