rule TTP_XOR_MULT_DOSStub_59ef {
  strings:
    $key_59ef = { 0d 87 [2] 79 9f [2] 3e 9d [2] 79 8c [2] 37 80 [2] 3b 8a [2] 2c 81 [2] 37 cf [2] 0a }

  condition:
    any of them
}