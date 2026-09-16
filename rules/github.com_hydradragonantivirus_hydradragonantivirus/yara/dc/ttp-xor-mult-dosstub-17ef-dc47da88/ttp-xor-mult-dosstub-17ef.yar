rule TTP_XOR_MULT_DOSStub_17ef {
  strings:
    $key_17ef = { 43 87 [2] 37 9f [2] 70 9d [2] 37 8c [2] 79 80 [2] 75 8a [2] 62 81 [2] 79 cf [2] 44 }

  condition:
    any of them
}