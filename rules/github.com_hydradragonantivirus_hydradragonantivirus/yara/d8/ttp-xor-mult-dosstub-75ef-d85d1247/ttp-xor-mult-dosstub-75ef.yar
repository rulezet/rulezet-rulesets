rule TTP_XOR_MULT_DOSStub_75ef {
  strings:
    $key_75ef = { 21 87 [2] 55 9f [2] 12 9d [2] 55 8c [2] 1b 80 [2] 17 8a [2] 00 81 [2] 1b cf [2] 26 }

  condition:
    any of them
}