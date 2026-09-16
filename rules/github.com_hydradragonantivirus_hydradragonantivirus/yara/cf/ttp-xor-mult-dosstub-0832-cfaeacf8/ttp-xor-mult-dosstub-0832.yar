rule TTP_XOR_MULT_DOSStub_0832 {
  strings:
    $key_0832 = { 5c 5a [2] 28 42 [2] 6f 40 [2] 28 51 [2] 66 5d [2] 6a 57 [2] 7d 5c [2] 66 12 [2] 5b }

  condition:
    any of them
}