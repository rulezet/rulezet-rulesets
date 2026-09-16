rule TTP_XOR_MULT_DOSStub_4d12 {
  strings:
    $key_4d12 = { 19 7a [2] 6d 62 [2] 2a 60 [2] 6d 71 [2] 23 7d [2] 2f 77 [2] 38 7c [2] 23 32 [2] 1e }

  condition:
    any of them
}