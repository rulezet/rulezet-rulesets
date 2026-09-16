rule TTP_XOR_MULT_DOSStub_4c25 {
  strings:
    $key_4c25 = { 18 4d [2] 6c 55 [2] 2b 57 [2] 6c 46 [2] 22 4a [2] 2e 40 [2] 39 4b [2] 22 05 [2] 1f }

  condition:
    any of them
}