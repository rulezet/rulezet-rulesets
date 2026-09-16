rule TTP_XOR_MULT_DOSStub_60ef {
  strings:
    $key_60ef = { 34 87 [2] 40 9f [2] 07 9d [2] 40 8c [2] 0e 80 [2] 02 8a [2] 15 81 [2] 0e cf [2] 33 }

  condition:
    any of them
}