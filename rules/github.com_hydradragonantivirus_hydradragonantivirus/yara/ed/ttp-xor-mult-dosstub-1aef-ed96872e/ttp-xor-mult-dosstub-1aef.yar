rule TTP_XOR_MULT_DOSStub_1aef {
  strings:
    $key_1aef = { 4e 87 [2] 3a 9f [2] 7d 9d [2] 3a 8c [2] 74 80 [2] 78 8a [2] 6f 81 [2] 74 cf [2] 49 }

  condition:
    any of them
}