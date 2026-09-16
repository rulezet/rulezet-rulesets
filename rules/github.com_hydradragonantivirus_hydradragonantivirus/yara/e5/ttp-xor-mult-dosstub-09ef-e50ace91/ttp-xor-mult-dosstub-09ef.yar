rule TTP_XOR_MULT_DOSStub_09ef {
  strings:
    $key_09ef = { 5d 87 [2] 29 9f [2] 6e 9d [2] 29 8c [2] 67 80 [2] 6b 8a [2] 7c 81 [2] 67 cf [2] 5a }

  condition:
    any of them
}