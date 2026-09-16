rule TTP_XOR_MULT_DOSStub_0829 {
  strings:
    $key_0829 = { 5c 41 [2] 28 59 [2] 6f 5b [2] 28 4a [2] 66 46 [2] 6a 4c [2] 7d 47 [2] 66 09 [2] 5b }

  condition:
    any of them
}