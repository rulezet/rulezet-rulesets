rule TTP_XOR_MULT_DOSStub_64ef {
  strings:
    $key_64ef = { 30 87 [2] 44 9f [2] 03 9d [2] 44 8c [2] 0a 80 [2] 06 8a [2] 11 81 [2] 0a cf [2] 37 }

  condition:
    any of them
}