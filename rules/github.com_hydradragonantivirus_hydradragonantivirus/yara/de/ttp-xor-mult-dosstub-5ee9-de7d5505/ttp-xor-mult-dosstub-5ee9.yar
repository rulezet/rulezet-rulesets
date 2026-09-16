rule TTP_XOR_MULT_DOSStub_5ee9 {
  strings:
    $key_5ee9 = { 0a 81 [2] 7e 99 [2] 39 9b [2] 7e 8a [2] 30 86 [2] 3c 8c [2] 2b 87 [2] 30 c9 [2] 0d }

  condition:
    any of them
}