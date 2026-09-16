rule TTP_XOR_MULT_DOSStub_3212 {
  strings:
    $key_3212 = { 66 7a [2] 12 62 [2] 55 60 [2] 12 71 [2] 5c 7d [2] 50 77 [2] 47 7c [2] 5c 32 [2] 61 }

  condition:
    any of them
}