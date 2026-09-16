rule TTP_XOR_MULT_DOSStub_27ef {
  strings:
    $key_27ef = { 73 87 [2] 07 9f [2] 40 9d [2] 07 8c [2] 49 80 [2] 45 8a [2] 52 81 [2] 49 cf [2] 74 }

  condition:
    any of them
}