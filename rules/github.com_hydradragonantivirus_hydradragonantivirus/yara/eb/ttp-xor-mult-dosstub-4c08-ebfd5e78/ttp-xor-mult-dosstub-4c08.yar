rule TTP_XOR_MULT_DOSStub_4c08 {
  strings:
    $key_4c08 = { 18 60 [2] 6c 78 [2] 2b 7a [2] 6c 6b [2] 22 67 [2] 2e 6d [2] 39 66 [2] 22 28 [2] 1f }

  condition:
    any of them
}