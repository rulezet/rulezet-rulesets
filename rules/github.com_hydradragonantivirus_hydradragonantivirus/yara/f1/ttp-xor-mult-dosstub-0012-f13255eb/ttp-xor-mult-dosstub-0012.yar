rule TTP_XOR_MULT_DOSStub_0012 {
  strings:
    $key_0012 = { 54 7a [2] 20 62 [2] 67 60 [2] 20 71 [2] 6e 7d [2] 62 77 [2] 75 7c [2] 6e 32 [2] 53 }

  condition:
    any of them
}