rule TTP_XOR_MULT_DOSStub_7ee4 {
  strings:
    $key_7ee4 = { 2a 8c [2] 5e 94 [2] 19 96 [2] 5e 87 [2] 10 8b [2] 1c 81 [2] 0b 8a [2] 10 c4 [2] 2d }

  condition:
    any of them
}