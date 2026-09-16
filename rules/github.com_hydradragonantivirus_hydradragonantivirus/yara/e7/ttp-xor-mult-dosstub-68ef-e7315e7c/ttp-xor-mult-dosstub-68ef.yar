rule TTP_XOR_MULT_DOSStub_68ef {
  strings:
    $key_68ef = { 3c 87 [2] 48 9f [2] 0f 9d [2] 48 8c [2] 06 80 [2] 0a 8a [2] 1d 81 [2] 06 cf [2] 3b }

  condition:
    any of them
}