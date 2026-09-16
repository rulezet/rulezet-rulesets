rule TTP_XOR_MULT_DOSStub_5904 {
  strings:
    $key_5904 = { 0d 6c [2] 79 74 [2] 3e 76 [2] 79 67 [2] 37 6b [2] 3b 61 [2] 2c 6a [2] 37 24 [2] 0a }

  condition:
    any of them
}