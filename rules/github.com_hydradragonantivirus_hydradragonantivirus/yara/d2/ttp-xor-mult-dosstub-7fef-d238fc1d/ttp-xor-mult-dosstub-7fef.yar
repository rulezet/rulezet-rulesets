rule TTP_XOR_MULT_DOSStub_7fef {
  strings:
    $key_7fef = { 2b 87 [2] 5f 9f [2] 18 9d [2] 5f 8c [2] 11 80 [2] 1d 8a [2] 0a 81 [2] 11 cf [2] 2c }

  condition:
    any of them
}