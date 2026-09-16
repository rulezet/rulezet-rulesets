rule TTP_XOR_MULT_DOSStub_4bef {
  strings:
    $key_4bef = { 1f 87 [2] 6b 9f [2] 2c 9d [2] 6b 8c [2] 25 80 [2] 29 8a [2] 3e 81 [2] 25 cf [2] 18 }

  condition:
    any of them
}