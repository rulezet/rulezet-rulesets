rule TTP_XOR_MULT_DOSStub_42ef {
  strings:
    $key_42ef = { 16 87 [2] 62 9f [2] 25 9d [2] 62 8c [2] 2c 80 [2] 20 8a [2] 37 81 [2] 2c cf [2] 11 }

  condition:
    any of them
}