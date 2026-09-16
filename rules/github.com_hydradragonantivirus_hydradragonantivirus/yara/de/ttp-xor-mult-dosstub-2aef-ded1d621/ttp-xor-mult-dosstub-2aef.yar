rule TTP_XOR_MULT_DOSStub_2aef {
  strings:
    $key_2aef = { 7e 87 [2] 0a 9f [2] 4d 9d [2] 0a 8c [2] 44 80 [2] 48 8a [2] 5f 81 [2] 44 cf [2] 79 }

  condition:
    any of them
}