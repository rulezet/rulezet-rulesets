rule TTP_XOR_MULT_DOSStub_39ef {
  strings:
    $key_39ef = { 6d 87 [2] 19 9f [2] 5e 9d [2] 19 8c [2] 57 80 [2] 5b 8a [2] 4c 81 [2] 57 cf [2] 6a }

  condition:
    any of them
}