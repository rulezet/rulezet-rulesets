rule TTP_XOR_MULT_DOSStub_50ef {
  strings:
    $key_50ef = { 04 87 [2] 70 9f [2] 37 9d [2] 70 8c [2] 3e 80 [2] 32 8a [2] 25 81 [2] 3e cf [2] 03 }

  condition:
    any of them
}