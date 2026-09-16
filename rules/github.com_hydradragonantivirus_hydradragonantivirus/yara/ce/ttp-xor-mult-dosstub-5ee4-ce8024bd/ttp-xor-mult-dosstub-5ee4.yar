rule TTP_XOR_MULT_DOSStub_5ee4 {
  strings:
    $key_5ee4 = { 0a 8c [2] 7e 94 [2] 39 96 [2] 7e 87 [2] 30 8b [2] 3c 81 [2] 2b 8a [2] 30 c4 [2] 0d }

  condition:
    any of them
}