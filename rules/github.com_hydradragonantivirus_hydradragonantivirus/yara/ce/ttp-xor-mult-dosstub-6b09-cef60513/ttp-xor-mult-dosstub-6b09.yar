rule TTP_XOR_MULT_DOSStub_6b09 {
  strings:
    $key_6b09 = { 3f 61 [2] 4b 79 [2] 0c 7b [2] 4b 6a [2] 05 66 [2] 09 6c [2] 1e 67 [2] 05 29 [2] 38 }

  condition:
    any of them
}