rule TTP_XOR_MULT_DOSStub_3bef {
  strings:
    $key_3bef = { 6f 87 [2] 1b 9f [2] 5c 9d [2] 1b 8c [2] 55 80 [2] 59 8a [2] 4e 81 [2] 55 cf [2] 68 }

  condition:
    any of them
}