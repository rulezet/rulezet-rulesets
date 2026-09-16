rule TTP_XOR_MULT_DOSStub_7b09 {
  strings:
    $key_7b09 = { 2f 61 [2] 5b 79 [2] 1c 7b [2] 5b 6a [2] 15 66 [2] 19 6c [2] 0e 67 [2] 15 29 [2] 28 }

  condition:
    any of them
}