rule TTP_XOR_MULT_DOSStub_7909 {
  strings:
    $key_7909 = { 2d 61 [2] 59 79 [2] 1e 7b [2] 59 6a [2] 17 66 [2] 1b 6c [2] 0c 67 [2] 17 29 [2] 2a }

  condition:
    any of them
}