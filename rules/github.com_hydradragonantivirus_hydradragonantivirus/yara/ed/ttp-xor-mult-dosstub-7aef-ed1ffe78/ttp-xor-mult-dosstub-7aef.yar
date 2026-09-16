rule TTP_XOR_MULT_DOSStub_7aef {
  strings:
    $key_7aef = { 2e 87 [2] 5a 9f [2] 1d 9d [2] 5a 8c [2] 14 80 [2] 18 8a [2] 0f 81 [2] 14 cf [2] 29 }

  condition:
    any of them
}